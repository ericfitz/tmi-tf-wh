#!/bin/bash
#
# sync-llm-keys-aws.sh - Push rotated LLM API keys from ~/.keys to the EKS Secret
#
# The cyber keys rotate weekly (usually Friday). This compares each ~/.keys
# file with the value in the running Secret (sha256 prefixes only; values are
# never printed), rewrites the changed lines in the secrets tfvars under infra/aws,
# applies through a saved plan file, and restarts the deployment so the pod
# picks up the new env.
#
# Usage:
#   ./scripts/sync-llm-keys-aws.sh [--check] [--yes] [--profile PROFILE] [--context CTX]
#
#   --check    compare only; exit 1 if any key differs
#   --yes      apply without the confirmation prompt
#
# Defaults: profile=$AWS_PROFILE or tmi, context=tmi-eks.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="${PROJECT_ROOT}/infra/aws"
# live-secrets.auto.tfvars on Eric's machine; secrets.auto.tfvars per infra/aws/README.md
TFVARS="${TF_DIR}/live-secrets.auto.tfvars"
[[ -f "$TFVARS" ]] || TFVARS="${TF_DIR}/secrets.auto.tfvars"
PROFILE="${AWS_PROFILE:-tmi}"
CONTEXT="tmi-eks"
NAMESPACE="tmi-tf"
SECRET="tmi-tf-wh-secrets"
DEPLOYMENT="tmi-tf-wh"
CHECK=false
YES=false

# Secret key : ~/.keys file : variable that file exports
KEYS=(
    "OPENAI_CYBER_API_KEY:OPENAI_CYBER_API_KEY:OPENAI_API_KEY"
    "ANTHROPIC_CYBER_API_KEY:MYTHOS_API_KEY:ANTHROPIC_API_KEY"
    "ANTHROPIC_CVP_API_KEY:ANTHROPIC_API_KEY:ANTHROPIC_API_KEY"
)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) CHECK=true; shift ;;
        --yes) YES=true; shift ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --context) CONTEXT="$2"; shift 2 ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

for tool in kubectl terraform python3 shasum; do
    command -v "$tool" >/dev/null || { echo "$tool not found in PATH" >&2; exit 1; }
done
[[ -f "$TFVARS" ]] || { echo "Missing $TFVARS" >&2; exit 1; }

# Prints the value exported by a key file; runs in a subshell so nothing leaks.
local_value() {
    # shellcheck disable=SC1090  # key file chosen at runtime
    ( source "${HOME}/.keys/$1" >/dev/null 2>&1; printf '%s' "${!2:-}" )
}

pod_value() {
    kubectl --context "$CONTEXT" -n "$NAMESPACE" get secret "$SECRET" \
        -o "jsonpath={.data.$1}" | base64 -d
}

hash8() { shasum -a 256 | cut -c1-8; }

CHANGED=()
for entry in "${KEYS[@]}"; do
    IFS=: read -r name file var <<<"$entry"
    if [[ ! -f "${HOME}/.keys/${file}" ]]; then
        echo "${name}: ~/.keys/${file} not found, skipped" >&2
        continue
    fi
    local_hash=$(local_value "$file" "$var" | hash8)
    if [[ -z "$(local_value "$file" "$var")" ]]; then
        echo "${name}: ~/.keys/${file} does not export ${var}; stopping" >&2
        exit 1
    fi
    pod_hash=$(pod_value "$name" | hash8)
    if [[ "$local_hash" == "$pod_hash" ]]; then
        echo "${name}: unchanged (${local_hash})"
    else
        echo "${name}: CHANGED (pod ${pod_hash} -> local ${local_hash})"
        CHANGED+=("$entry")
    fi
done

if [[ ${#CHANGED[@]} -eq 0 ]]; then
    echo "All keys match the running Secret."
    exit 0
fi
[[ "$CHECK" == true ]] && exit 1

# Rewrite only the changed lines. The value goes through the environment,
# never argv, and is restricted to characters that need no HCL escaping.
umask 077
for entry in "${CHANGED[@]}"; do
    IFS=: read -r name file var <<<"$entry"
    KEY_NAME="$name" KEY_VALUE="$(local_value "$file" "$var")" TFVARS="$TFVARS" python3 - <<'EOF'
import os, re, sys
name, value, path = os.environ["KEY_NAME"], os.environ["KEY_VALUE"], os.environ["TFVARS"]
if not re.fullmatch(r"[A-Za-z0-9_.\-]+", value):
    sys.exit(f"{name}: value has characters that would need HCL escaping; not written")
text = open(path).read()
new, n = re.subn(rf'^(\s*{name}\s*=\s*)"[^"\n]*"', lambda m: f'{m.group(1)}"{value}"', text, flags=re.M)
if n != 1:
    sys.exit(f"{name}: expected 1 line in {path}, found {n}; not written")
open(path, "w").write(new)
print(f"{name}: tfvars line updated")
EOF
done

PLAN="$(mktemp "${TMPDIR:-/tmp}/sync-keys.XXXXXX")"
trap 'rm -f "$PLAN"' EXIT

AWS_PROFILE="$PROFILE" terraform -chdir="$TF_DIR" plan -input=false -out="$PLAN" -no-color \
    | grep -E '^\s+[~+-] resource|^Plan:|No changes'
if [[ "$YES" != true ]]; then
    read -r -p "Apply this plan and restart ${DEPLOYMENT}? [y/N] " answer
    [[ "$answer" == [yY] ]] || { echo "Not applied. tfvars keep the new values." >&2; exit 1; }
fi
AWS_PROFILE="$PROFILE" terraform -chdir="$TF_DIR" apply -input=false -no-color "$PLAN" \
    | grep -E '^Apply complete|Error'

kubectl --context "$CONTEXT" -n "$NAMESPACE" rollout restart "deploy/${DEPLOYMENT}"
kubectl --context "$CONTEXT" -n "$NAMESPACE" rollout status "deploy/${DEPLOYMENT}" --timeout=300s

for entry in "${CHANGED[@]}"; do
    IFS=: read -r name file var <<<"$entry"
    if [[ "$(pod_value "$name" | hash8)" == "$(local_value "$file" "$var" | hash8)" ]]; then
        echo "${name}: synced"
    else
        echo "${name}: Secret still differs after apply" >&2
        exit 1
    fi
done
