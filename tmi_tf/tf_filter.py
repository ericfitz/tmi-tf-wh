"""Registry-driven filtering of parsed Terraform (issue #10).

Produces the two phase-1 inputs -- filtered HCL and a pre-built inventory --
from a ``StaticInventory`` and ``tmi_tf/data/resource_registry.yaml``.
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import hcl2
import yaml  # pyright: ignore[reportMissingModuleSource]

from tmi_tf.tf_parser import (
    BLOCK_MARKER,
    StaticInventory,
    find_references,
    unquote_literal,
)

logger = logging.getLogger(__name__)

ALLOWED_CATEGORIES = frozenset(
    {
        "compute",
        "storage",
        "network",
        "gateway",
        "security_control",
        "identity",
        "monitoring",
        "dns",
        "cdn",
        "other",
    }
)
META_ARGS = frozenset({"count", "for_each", "depends_on", "provider", "lifecycle"})
# Meta-args that say nothing about the resource itself; kept in the HCL, not
# repeated in the inventory "configuration".
_CONFIG_EXCLUDED = frozenset({"depends_on", "provider", "lifecycle"})
REGISTRY_PATH = Path(__file__).parent / "data" / "resource_registry.yaml"


@dataclass(frozen=True)
class Registry:
    providers: dict[str, dict[str, str]]
    resources: dict[str, dict[str, Any]]
    hash_only_attrs: frozenset[str]
    unknown_category: str = "other"

    def category(self, resource_type: str) -> str:
        entry = self.resources.get(resource_type)
        return entry["category"] if entry else self.unknown_category

    def security_attrs(self, resource_type: str) -> list[str] | None:
        """Attribute paths to keep, or None for an unknown type (keep all)."""
        entry = self.resources.get(resource_type)
        return list(entry["security_attrs"]) if entry else None

    def provider_name(self, resource_type: str) -> str | None:
        best = ""
        for prefix in self.providers:
            if resource_type.startswith(prefix) and len(prefix) > len(best):
                best = prefix
        return self.providers[best]["name"] if best else None


def load_registry(path: Path = REGISTRY_PATH) -> Registry:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    for rtype, entry in raw["resources"].items():
        if entry.get("category") not in ALLOWED_CATEGORIES:
            raise ValueError(
                f"resource registry: {rtype} has invalid category {entry.get('category')!r}"
            )
        if not isinstance(entry.get("security_attrs"), list):
            raise TypeError(f"resource registry: {rtype} security_attrs must be a list")
    defaults = raw.get("defaults", {})
    return Registry(
        providers=raw["providers"],
        resources=raw["resources"],
        hash_only_attrs=frozenset(defaults.get("hash_only_attrs", [])),
        unknown_category=defaults.get("unknown_category", "other"),
    )


@dataclass
class FilterResult:
    filtered_files: dict[str, str] = field(default_factory=dict)
    prebuilt_inventory: dict[str, Any] = field(default_factory=dict)
    omitted_attributes: int = 0


# --- attribute selection ---------------------------------------------------


def _attr_tree(paths: list[str]) -> dict[str, Any]:
    """{"ami": None, "ebs_block_device": {"encrypted": None}}; None = keep whole."""
    tree: dict[str, Any] = {}
    for path in paths:
        node = tree
        parts = path.split(".")
        for part in parts[:-1]:
            if part in node and node[part] is None:
                break  # a parent path already keeps the whole subtree
            node = node.setdefault(part, {})
        else:
            node[parts[-1]] = None
    return tree


def _select(value: Any, tree: dict[str, Any]) -> Any:
    """Keep only keys present in ``tree`` (recursively through blocks/objects)."""
    if isinstance(value, list):
        return [_select(v, tree) for v in value]
    if not isinstance(value, dict):
        return value
    out: dict[str, Any] = {}
    for k, v in value.items():
        if k == BLOCK_MARKER:
            out[k] = v
        elif k in tree:
            out[k] = v if tree[k] is None else _select(v, tree[k])
        elif find_references(v):
            out[k] = v
    return out


def _filter_body(
    body: dict[str, Any], resource_type: str, registry: Registry
) -> tuple[dict[str, Any], int]:
    """(kept attributes in source order, number of omitted top-level attrs)."""
    attrs = registry.security_attrs(resource_type)
    if attrs is None:
        return dict(body), 0
    selected = _select(body, _attr_tree(attrs))
    kept: dict[str, Any] = {}
    for k, v in body.items():
        if k in selected:
            kept[k] = selected[k]
        elif k in META_ARGS or find_references(v):
            kept[k] = v
    # "__comments__"/"__is_block__" are hcl2 bookkeeping, not attributes
    omitted = sum(1 for k in body if not k.startswith("__") and k not in kept)
    return kept, omitted


def _script_digest(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    return f"[script omitted: sha256:{digest}, {len(text)} chars]"


def _hash_scripts(value: Any, names: frozenset[str], quoted: bool) -> Any:
    """Replace script-carrying attributes at any depth by a digest string.

    ``quoted`` wraps the digest in quotes so ``hcl2.dumps`` emits a literal.
    """
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k in names:
                digest = _script_digest(v)
                out[k] = f'"{digest}"' if quoted else digest
            else:
                out[k] = _hash_scripts(v, names, quoted)
        return out
    if isinstance(value, list):
        return [_hash_scripts(v, names, quoted) for v in value]
    return value


# --- filtered HCL ------------------------------------------------------------


def _render_resource(
    rtype_q: str, name_q: str, body: dict[str, Any], registry: Registry
) -> tuple[str, int]:
    kept, omitted = _filter_body(body, unquote_literal(rtype_q), registry)
    kept = _hash_scripts(kept, registry.hash_only_attrs, quoted=True)
    text = hcl2.dumps({"resource": [{rtype_q: {name_q: kept}}]}).rstrip()
    if omitted and text.endswith("}"):
        text = (
            f"{text[:-1].rstrip()}\n  # {omitted} non-security attributes omitted\n}}"
        )
    return text, omitted


def _render_file(parsed: dict[str, Any], registry: Registry) -> tuple[str, int]:
    """Regenerate one file's HCL with resource bodies filtered."""
    chunks: list[str] = []
    omitted_total = 0
    for block_type, items in parsed.items():
        if block_type.startswith("__"):
            continue  # __comments__ and friends
        if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
            # top-level attribute (.tfvars); block lists are lists of dicts
            chunks.append(hcl2.dumps({block_type: items}).rstrip())
            continue
        for item in items:
            if block_type == "resource":
                for rtype_q, by_name in item.items():
                    for name_q, body in by_name.items():
                        text, omitted = _render_resource(
                            rtype_q, name_q, body, registry
                        )
                        chunks.append(text)
                        omitted_total += omitted
            elif block_type == "module":
                # Module inputs aren't registry-filtered (no resource type to
                # look up), but script-carrying inputs still must not leak.
                item = {
                    label: _hash_scripts(body, registry.hash_only_attrs, quoted=True)
                    for label, body in item.items()
                }
                chunks.append(hcl2.dumps({block_type: [item]}).rstrip())
            else:
                chunks.append(hcl2.dumps({block_type: [item]}).rstrip())
    return ("\n\n".join(chunks) + "\n") if chunks else "", omitted_total


# --- pre-built inventory ------------------------------------------------------


def _configuration(
    attributes: dict[str, Any], resource_type: str, registry: Registry
) -> dict[str, Any]:
    attrs = registry.security_attrs(resource_type)
    cfg = attributes if attrs is None else _select(attributes, _attr_tree(attrs))
    cfg = {k: v for k, v in cfg.items() if k not in _CONFIG_EXCLUDED}
    return _hash_scripts(cfg, registry.hash_only_attrs, quoted=False)


def _component(
    cid: str,
    resource_type: str,
    category: str,
    provider: str | None,
    file: str,
    configuration: dict[str, Any],
    references: list[str],
) -> dict[str, Any]:
    return {
        "id": cid,
        "resource_type": resource_type,
        "type": category,
        "provider": provider,
        "file": file,
        "configuration": configuration,
        "references": references,
        "name": None,
        "purpose": None,
    }


def _prebuilt_inventory(
    inventory: StaticInventory, registry: Registry
) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for r in inventory.resources:
        components.append(
            _component(
                r.address,
                r.resource_type,
                registry.category(r.resource_type),
                registry.provider_name(r.resource_type),
                r.file,
                _configuration(r.attributes, r.resource_type, registry),
                r.references,
            )
        )
    for d in inventory.data_sources:
        components.append(
            _component(
                d.address,
                d.data_type,
                registry.category(d.data_type),
                registry.provider_name(d.data_type),
                d.file,
                _hash_scripts(d.attributes, registry.hash_only_attrs, quoted=False),
                d.references,
            )
        )
    for m in inventory.modules:
        references = find_references({"inputs": _requote(m.inputs)})
        inputs = _hash_scripts(m.inputs, registry.hash_only_attrs, quoted=False)
        components.append(
            _component(
                f"module.{m.name}",
                "module",
                "other",
                None,
                m.file,
                {"source": m.source, "inputs": inputs},
                references,
            )
        )
    variables = []
    for v in inventory.variables:
        entry: dict[str, Any] = {"name": v.name, "type": v.type_expr}
        if not v.sensitive:
            entry["default"] = v.default
        entry["description"] = v.description
        variables.append(entry)
    return {
        "components": components,
        "variables": variables,
        "outputs": [
            {
                "name": o.name,
                "description": o.description,
                "sensitive": o.sensitive,
                "value": o.value_expr,
            }
            for o in inventory.outputs
        ],
        "modules": [
            {"id": f"module.{m.name}", "source": m.source, "file": m.file}
            for m in inventory.modules
        ],
        "unparsed_files": list(inventory.unparsed_files),
    }


def _requote(value: Any) -> Any:
    """Cleaned values back to the ``${...}`` form so find_references sees them."""
    if isinstance(value, dict):
        return {k: _requote(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_requote(v) for v in value]
    if isinstance(value, str):
        return f"${{{value}}}"
    return value


def filter_terraform(
    inventory: StaticInventory, tf_contents: dict[str, str], registry: Registry
) -> FilterResult:
    """Filtered HCL per file (raw for unparsed files) plus the pre-built inventory."""
    result = FilterResult(prebuilt_inventory=_prebuilt_inventory(inventory, registry))
    for path in sorted(tf_contents):
        if path in inventory.parsed_files:
            text, omitted = _render_file(inventory.parsed_files[path], registry)
            result.filtered_files[path] = text
            result.omitted_attributes += omitted
        else:
            result.filtered_files[path] = tf_contents[path]
    logger.info(
        "Static HCL filter: %d components, %d attributes omitted, %d/%d files unparsed",
        len(result.prebuilt_inventory["components"]),
        result.omitted_attributes,
        len(inventory.unparsed_files),
        len(tf_contents),
    )
    return result
