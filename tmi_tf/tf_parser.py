"""Static HCL parsing of Terraform files with python-hcl2 (issue #10).

python-hcl2 8.x conventions this module relies on:
  string literals keep their quotes   '"ami-123"'
  expressions are wrapped             '${aws_subnet.private.id}'
  nested blocks are lists of dicts    [{"encrypted": True, "__is_block__": True}]
  block labels keep their quotes      {'"aws_instance"': {'"web"': body}}
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

import hcl2

logger = logging.getLogger(__name__)

BLOCK_MARKER = "__is_block__"

# resource_type.name | data.type.name | module.name -- never var./local./each./
# path./count./self.: the lookbehind refuses a match right after a dot and the
# resource alternative requires an underscore in the type.
_REF_RE = re.compile(
    r"(?<![\w.])(data\.[a-z][a-z0-9_]*|module|[a-z][a-z0-9]*_[a-z0-9_]*)"
    r"\.([A-Za-z_][\w-]*)"
)


@dataclass
class ParsedResource:
    resource_type: str
    local_name: str
    address: str
    file: str
    attributes: dict[str, Any]
    references: list[str]


@dataclass
class ParsedDataSource:
    data_type: str
    local_name: str
    address: str
    file: str
    attributes: dict[str, Any]
    references: list[str]


@dataclass
class ParsedVariable:
    name: str
    type_expr: str | None
    default: Any
    description: str | None
    sensitive: bool


@dataclass
class ParsedOutput:
    name: str
    value_expr: str
    description: str | None
    sensitive: bool


@dataclass
class ParsedModule:
    name: str
    source: str
    inputs: dict[str, Any]
    file: str


@dataclass
class ParsedProvider:
    name: str
    alias: str | None
    config: dict[str, Any]


@dataclass
class StaticInventory:
    resources: list[ParsedResource] = field(default_factory=list)
    data_sources: list[ParsedDataSource] = field(default_factory=list)
    variables: list[ParsedVariable] = field(default_factory=list)
    outputs: list[ParsedOutput] = field(default_factory=list)
    modules: list[ParsedModule] = field(default_factory=list)
    providers: list[ParsedProvider] = field(default_factory=list)
    unparsed_files: list[str] = field(default_factory=list)
    # Raw hcl2 dict per parsed file; tf_filter regenerates HCL from these.
    parsed_files: dict[str, dict[str, Any]] = field(default_factory=dict)


def unquote_literal(s: str) -> str:
    """'"x"' -> 'x'; anything else unchanged."""
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def clean_value(value: Any) -> Any:
    """Human-readable form: drop hcl2 bookkeeping keys (``__is_block__``,
    ``__comments__``), unquote literals, unwrap ${expr}."""
    if isinstance(value, dict):
        return {k: clean_value(v) for k, v in value.items() if not k.startswith("__")}
    if isinstance(value, list):
        return [clean_value(v) for v in value]
    if isinstance(value, str):
        if value.startswith("${") and value.endswith("}") and value.count("${") == 1:
            return value[2:-1]
        return unquote_literal(value)
    return value


def find_references(value: Any, exclude: str = "") -> list[str]:
    """Terraform addresses referenced anywhere inside ``value``.

    Only expression strings (containing ``${``) are scanned, so a quoted literal
    such as ``"owner_team.name"`` is not mistaken for a reference.
    """
    refs: set[str] = set()

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for item in v.values():
                walk(item)
        elif isinstance(v, list):
            for item in v:
                walk(item)
        elif isinstance(v, str) and "${" in v:
            for m in _REF_RE.finditer(v):
                refs.add(f"{m.group(1)}.{m.group(2)}")

    walk(value)
    refs.discard(exclude)
    return sorted(refs)


def _labelled(item: dict[str, Any]) -> list[tuple[str, Any]]:
    """[(label, body)] for a one-label block item like {'"aws"': body}."""
    return [(unquote_literal(k), v) for k, v in item.items()]


def _optional_str(body: dict[str, Any], key: str) -> str | None:
    value = body.get(key)
    return None if value is None else str(clean_value(value))


def _collect(inv: StaticInventory, path: str, parsed: dict[str, Any]) -> None:
    for item in parsed.get("resource", []):
        for rtype, by_name in _labelled(item):
            for name, body in _labelled(by_name):
                address = f"{rtype}.{name}"
                inv.resources.append(
                    ParsedResource(
                        resource_type=rtype,
                        local_name=name,
                        address=address,
                        file=path,
                        attributes=clean_value(body),
                        references=find_references(body, exclude=address),
                    )
                )
    for item in parsed.get("data", []):
        for dtype, by_name in _labelled(item):
            for name, body in _labelled(by_name):
                address = f"data.{dtype}.{name}"
                inv.data_sources.append(
                    ParsedDataSource(
                        data_type=dtype,
                        local_name=name,
                        address=address,
                        file=path,
                        attributes=clean_value(body),
                        references=find_references(body, exclude=address),
                    )
                )
    for item in parsed.get("variable", []):
        for name, body in _labelled(item):
            inv.variables.append(
                ParsedVariable(
                    name=name,
                    type_expr=_optional_str(body, "type"),
                    default=clean_value(body.get("default")),
                    description=_optional_str(body, "description"),
                    sensitive=body.get("sensitive") is True,
                )
            )
    for item in parsed.get("output", []):
        for name, body in _labelled(item):
            inv.outputs.append(
                ParsedOutput(
                    name=name,
                    value_expr=str(clean_value(body.get("value", ""))),
                    description=_optional_str(body, "description"),
                    sensitive=body.get("sensitive") is True,
                )
            )
    for item in parsed.get("module", []):
        for name, body in _labelled(item):
            attrs = clean_value(body)
            source = str(attrs.pop("source", ""))
            for meta in ("version", "providers", "depends_on", "count", "for_each"):
                attrs.pop(meta, None)
            inv.modules.append(
                ParsedModule(name=name, source=source, inputs=attrs, file=path)
            )
    for item in parsed.get("provider", []):
        for name, body in _labelled(item):
            config = clean_value(body)
            alias = config.pop("alias", None)
            inv.providers.append(
                ParsedProvider(
                    name=name,
                    alias=None if alias is None else str(alias),
                    config=config,
                )
            )


def parse_terraform(tf_contents: dict[str, str]) -> StaticInventory:
    """Parse every file; files python-hcl2 rejects go to ``unparsed_files``.

    ``tf_contents`` is ``TerraformRepository.get_terraform_content()`` output
    (relative path -> text), i.e. the environment plus resolved modules after
    sanitization.
    """
    inv = StaticInventory()
    for path in sorted(tf_contents):
        try:
            parsed = hcl2.loads(tf_contents[path])
        except Exception as e:
            # lark errors and the occasional transformer bug (AttributeError on
            # python-hcl2 8.1.4) alike: the LLM still sees the raw file.
            logger.warning("Static HCL parse failed for %s: %s", path, e)
            inv.unparsed_files.append(path)
            continue
        inv.parsed_files[path] = parsed
        _collect(inv, path, parsed)
    return inv
