"""Tests for registry-driven filtering and the pre-built inventory (issue #10)."""

import itertools
import json
import re
from pathlib import Path

import hcl2
import pytest  # type: ignore

from tmi_tf.script_scan import extract_scripts
from tmi_tf.tf_filter import (
    ALLOWED_CATEGORIES,
    REGISTRY_PATH,
    FilterResult,
    Registry,
    filter_terraform,
    load_registry,
    prompt_inventory,
    prompt_inventory_json,
)
from tmi_tf.tf_parser import parse_terraform

FIXTURES = Path(__file__).parent / "fixtures" / "tf"
RESOURCE_BLOCK_RE = re.compile(r'^resource\s+"', re.MULTILINE)


def _load(*names: str) -> dict[str, str]:
    return {n: (FIXTURES / n).read_text(encoding="utf-8") for n in names}


@pytest.fixture(scope="module")
def registry() -> Registry:
    return load_registry()


def _run(registry: Registry, *names: str) -> FilterResult:
    contents = _load(*names)
    return filter_terraform(parse_terraform(contents), contents, registry)


def _component(result: FilterResult, cid: str) -> dict:
    return next(c for c in result.prebuilt_inventory["components"] if c["id"] == cid)


class TestRegistry:
    def test_load_registry_from_package(self, registry):
        assert REGISTRY_PATH.exists()
        assert registry.category("aws_instance") == "compute"
        assert registry.category("mycorp_widget") == "other"
        assert registry.security_attrs("mycorp_widget") is None
        assert "ami" in (registry.security_attrs("aws_instance") or [])
        assert registry.provider_name("aws_instance") == "AWS"
        assert registry.provider_name("azurerm_subnet") == "Microsoft Azure"
        assert registry.provider_name("mycorp_widget") is None
        assert "user_data" in registry.hash_only_attrs

    def test_invalid_category_is_rejected(self, tmp_path):
        bad = tmp_path / "r.yaml"
        bad.write_text(
            "providers: {aws_: {name: AWS, type: cloud}}\n"
            "resources: {aws_x: {category: bogus, security_attrs: []}}\n"
            "defaults: {unknown_category: other, unknown_attrs: all, hash_only_attrs: []}\n"
        )
        with pytest.raises(ValueError, match="aws_x"):
            load_registry(bad)


class TestFilteredHcl:
    def test_security_attrs_kept_others_omitted_with_comment(self, registry):
        hcl = _run(registry, "aws.tf").filtered_files["aws.tf"]
        block = hcl[hcl.index('resource "aws_instance" "web"') :]
        block = block[: block.index("\n}") + 2]
        assert "ami" in block
        assert "subnet_id" in block
        assert "associate_public_ip_address = false" in block
        assert "encrypted = true" in block
        assert "volume_size" not in block  # nested attr not in registry path list
        assert "instance_type" not in block
        assert "tags" not in block
        # count/for_each/depends_on/provider/lifecycle are always kept
        assert "depends_on" in block
        assert "# 2 non-security attributes omitted" in block  # instance_type, tags

    def test_reference_attributes_are_kept_even_if_not_security(self, registry):
        # "tags" is not a security attr of aws_s3_bucket, but it holds a reference
        contents = {
            "m.tf": (
                'resource "aws_s3_bucket" "b" {\n'
                '  bucket = "x"\n'
                "  tags   = { owner = aws_iam_role.web.name }\n"
                '  region = "us-east-1"\n'
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert "aws_iam_role.web.name" in hcl
        assert "region" not in hcl
        assert "# 1 non-security attributes omitted" in hcl

    def test_nested_reference_kept_even_if_not_a_registry_path(self, registry):
        # "snapshot_id" is not itself a registry security_attrs path for
        # aws_instance (only ebs_block_device.encrypted/.kms_key_id are), but
        # it holds a reference nested inside a registry-selected block.
        contents = {
            "m.tf": (
                'resource "aws_instance" "w" {\n'
                '  ami = "ami-1"\n'
                "  ebs_block_device {\n"
                "    encrypted   = true\n"
                "    snapshot_id = aws_ebs_snapshot.s.id\n"
                "  }\n"
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert "aws_ebs_snapshot.s.id" in hcl

    def test_escaped_quote_in_kept_attr_survives_round_trip(self, registry):
        # carried item: unquote_literal doesn't unescape \" -- confirm the
        # filtered HCL (re-emitted via hcl2.dumps) still parses back cleanly.
        contents = {
            "m.tf": (
                'resource "aws_instance" "web" {\n  ami = "ami-\\"escaped\\""\n}\n'
            )
        }
        original = parse_terraform(contents)
        res = filter_terraform(original, contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert 'ami = "ami-\\"escaped\\""' in hcl
        # Filtering must not further mangle the (already-imperfect, per Task 1's
        # carried-item note) unescaping -- the value is stable across the
        # filter's hcl2.dumps/hcl2.loads round trip, not further corrupted.
        reparsed = parse_terraform({"m.tf": hcl})
        assert reparsed.unparsed_files == []
        assert (
            reparsed.resources[0].attributes["ami"]
            == original.resources[0].attributes["ami"]
        )

    def test_unknown_resource_keeps_everything(self, registry):
        hcl = _run(registry, "aws.tf").filtered_files["aws.tf"]
        assert 'resource "mycorp_widget" "custom"' in hcl
        assert "size  = 3" in hcl or "size = 3" in hcl
        assert 'color = "blue"' in hcl
        widget = hcl[hcl.index('resource "mycorp_widget"') :]
        widget = widget[: widget.index("\n}") + 2]
        assert "omitted" not in widget

    def test_non_resource_blocks_pass_through(self, registry):
        hcl = _run(registry, "aws.tf").filtered_files["aws.tf"]
        for needle in (
            'data "aws_ami" "ubuntu"',
            'variable "region"',
            'output "instance_ip"',
            'module "dns"',
            'provider "aws"',
            "terraform {",
            "locals {",
        ):
            assert needle in hcl, needle

    def test_unparsed_file_passes_through_raw(self, registry):
        res = _run(registry, "aws.tf", "broken.tf")
        assert res.filtered_files["broken.tf"] == (FIXTURES / "broken.tf").read_text()
        assert res.prebuilt_inventory["unparsed_files"] == ["broken.tf"]

    def test_tfvars_file_passes_through(self, registry):
        contents = {
            "terraform.tfvars": 'region = "us-east-1"\n',
            "e.tf": "",
            "c.tf": "# c\n",
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        assert 'region = "us-east-1"' in res.filtered_files["terraform.tfvars"]
        assert res.filtered_files["e.tf"] == ""
        assert res.prebuilt_inventory["components"] == []

    def test_tfvars_object_list_round_trips_as_single_assignment(self, registry):
        # Finding 3: a .tfvars attribute whose value is a list of objects must
        # not be mistaken for a block list (which would render N separate
        # `rules = [...]` assignments instead of one).
        contents = {"x.tfvars": "rules = [{ port = 80 }, { port = 443 }]\n"}
        res = filter_terraform(parse_terraform(contents), contents, registry)
        text = res.filtered_files["x.tfvars"]
        assert text.count("rules") == 1
        assert hcl2.loads(text) == {"rules": [{"port": 80}, {"port": 443}]}

    def test_registry_attrs_absent_from_block(self, registry):
        contents = {"m.tf": 'resource "aws_kms_alias" "a" {\n  foo = 1\n  bar = 2\n}\n'}
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert 'resource "aws_kms_alias" "a"' in hcl
        assert "foo" not in hcl and "bar" not in hcl
        assert "# 2 non-security attributes omitted" in hcl
        assert res.omitted_attributes == 2

    def test_comments_are_not_attributes(self, registry):
        contents = {
            "m.tf": (
                'resource "aws_kms_alias" "a" {\n'
                "  # why this alias exists\n"
                '  name = "alias/x" # trailing\n'
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        assert res.omitted_attributes == 0
        assert "omitted" not in res.filtered_files["m.tf"]
        assert _component(res, "aws_kms_alias.a")["configuration"] == {
            "name": "alias/x"
        }

    def test_script_attributes_are_hashed_everywhere(self, registry):
        res = _run(registry, "aws.tf", "azure.tf", "gcp.tf", "oci.tf")
        for path in ("aws.tf", "azure.tf", "gcp.tf", "oci.tf"):
            assert "echo hi" not in res.filtered_files[path]
            assert "echo hello" not in res.filtered_files[path]
        dumped = json.dumps(res.prebuilt_inventory)
        assert "echo hi" not in dumped and "echo hello" not in dumped
        aws = _component(res, "aws_instance.web")
        assert aws["configuration"]["user_data"].startswith("[script omitted: sha256:")
        gcp = _component(res, "google_compute_instance.web")
        assert gcp["configuration"]["metadata"]["startup-script"].startswith(
            "[script omitted: sha256:"
        )
        oci = _component(res, "oci_core_instance.web")
        assert oci["configuration"]["metadata"]["user_data"].startswith(
            "[script omitted: sha256:"
        )

    def test_configuration_digest_matches_scriptblob_digest(self, registry):
        # #14 fix: _configuration used to hash the clean_value'd (unquoted)
        # script text, producing a different digest than the filtered HCL
        # (_render_resource) and ScriptBlob (script_scan.py) -- both of which
        # hash the raw, pre-clean_value hcl2 value. All three must agree so
        # the same script isn't shown under two different digests.
        contents = _load("aws.tf")
        static = parse_terraform(contents)
        res = filter_terraform(static, contents, registry)
        blobs = extract_scripts(static, contents, registry)
        blob = next(b for b in blobs if b.id == "aws_instance.web:user_data")
        aws = _component(res, "aws_instance.web")
        assert aws["configuration"]["user_data"] == blob.digest
        assert "[script omitted: sha256:" in res.filtered_files["aws.tf"]
        assert blob.digest in res.filtered_files["aws.tf"]

    def test_data_and_module_script_digests_match_scriptblob(self, registry):
        contents = {
            "m.tf": (
                'data "cloudinit_config" "ci" {\n'
                "  part {\n"
                "    content = <<-EOT\n"
                "      #!/bin/bash\n"
                "      echo hi\n"
                "    EOT\n"
                "  }\n"
                "}\n"
                'module "vm" {\n'
                '  source    = "./vm"\n'
                '  user_data = "echo mod"\n'
                "}\n"
            )
        }
        static = parse_terraform(contents)
        res = filter_terraform(static, contents, registry)
        blobs = {b.id: b.digest for b in extract_scripts(static, contents, registry)}
        ci_digest = blobs["data.cloudinit_config.ci:part.content"]
        mod_digest = blobs["module.vm:user_data"]
        ci = _component(res, "data.cloudinit_config.ci")
        assert ci["configuration"]["part"][0]["content"] == ci_digest
        mod = _component(res, "module.vm")
        assert mod["configuration"]["inputs"]["user_data"] == mod_digest
        assert ci_digest in res.filtered_files["m.tf"]
        assert mod_digest in res.filtered_files["m.tf"]

    def test_dynamic_block_is_kept_in_filtered_hcl_and_configuration(self, registry):
        # Finding 1: hcl2 parses `dynamic "ingress" { ... }` under the key
        # "dynamic", which is neither a registry attr nor a meta-arg, so it
        # must be force-kept rather than dropped as a non-security attribute.
        contents = {
            "m.tf": (
                'resource "aws_security_group" "web" {\n'
                '  name   = "web"\n'
                "  vpc_id = aws_vpc.main.id\n"
                "\n"
                '  dynamic "ingress" {\n'
                "    for_each = var.rules\n"
                "    content {\n"
                "      from_port = ingress.value.from\n"
                "      to_port   = ingress.value.to\n"
                '      protocol  = "tcp"\n'
                '      user_data = "echo hi"\n'
                "    }\n"
                "  }\n"
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert 'dynamic "ingress"' in hcl
        assert "for_each" in hcl
        assert "from_port" in hcl
        assert "non-security attributes omitted" not in hcl
        assert "echo hi" not in hcl
        assert "[script omitted: sha256:" in hcl
        assert res.omitted_attributes == 0

        cfg = _component(res, "aws_security_group.web")["configuration"]
        assert "dynamic" in cfg
        ingress = cfg["dynamic"][0]['"ingress"']
        assert ingress["content"][0]["user_data"].startswith("[script omitted: sha256:")

    def test_variable_validation_block_is_dropped_with_comment(self, registry):
        contents = {
            "m.tf": (
                'variable "x" {\n'
                "  type        = string\n"
                '  default     = "d"\n'
                '  description = "desc"\n'
                "  sensitive   = false\n"
                "  nullable    = true\n"
                "  validation {\n"
                "    condition     = length(var.x) > 0\n"
                '    error_message = "must not be empty"\n'
                "  }\n"
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert 'variable "x"' in hcl
        assert "type" in hcl
        assert 'default     = "d"' in hcl or "default = " in hcl
        assert "description" in hcl
        assert "sensitive" in hcl
        assert "nullable" in hcl
        assert "validation" not in hcl
        assert "error_message" not in hcl
        assert "# 1 non-security attributes omitted" in hcl
        assert res.omitted_attributes == 1

    def test_variable_without_validation_is_untouched(self, registry):
        contents = {"m.tf": 'variable "x" {\n  type = string\n}\n'}
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert "omitted" not in hcl
        assert res.omitted_attributes == 0

    def test_output_blocks_are_never_touched_by_validation_stripping(self, registry):
        hcl = _run(registry, "aws.tf").filtered_files["aws.tf"]
        assert 'output "instance_ip"' in hcl
        block = hcl[hcl.index('output "instance_ip"') :]
        block = block[: block.index("\n}") + 2]
        assert "omitted" not in block

    def test_data_block_scripts_are_hashed(self, registry):
        contents = {
            "m.tf": (
                'data "template_file" "x" {\n'
                '  template = "#!/bin/bash\\necho DATASECRET"\n'
                "}\n"
                'data "cloudinit_config" "y" {\n'
                "  part {\n"
                '    content = "echo PARTSECRET"\n'
                "  }\n"
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert "DATASECRET" not in hcl
        assert "PARTSECRET" not in hcl
        assert "[script omitted: sha256:" in hcl
        dumped = json.dumps(res.prebuilt_inventory)
        assert "DATASECRET" not in dumped and "PARTSECRET" not in dumped

    def test_content_attr_not_hashed_outside_data_blocks(self, registry):
        # "content"/"template" are too generic to hash everywhere (e.g.
        # local_file.content); only data blocks get the extra names.
        contents = {
            "m.tf": 'resource "mycorp_widget" "w" {\n  content = "echo SHOULDSTAY"\n}\n'
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert "echo SHOULDSTAY" in hcl
        assert "[script omitted" not in hcl
        cfg = _component(res, "mycorp_widget.w")["configuration"]
        assert cfg["content"] == "echo SHOULDSTAY"

    def test_render_file_error_falls_back_to_raw_for_that_file_only(
        self, registry, monkeypatch, caplog
    ):
        import tmi_tf.tf_filter as tf_filter_mod

        contents = {
            "good.tf": 'resource "aws_kms_alias" "a" {\n  name = "x"\n}\n',
            "bad.tf": 'resource "aws_kms_alias" "b" {\n  name = "y"\n}\n',
        }
        inventory = parse_terraform(contents)
        original_dumps = tf_filter_mod.hcl2.dumps

        def flaky_dumps(data, *args, **kwargs):
            for item in data.get("resource", []):
                if '"b"' in item.get('"aws_kms_alias"', {}):
                    raise RuntimeError("boom")
            return original_dumps(data, *args, **kwargs)

        monkeypatch.setattr(tf_filter_mod.hcl2, "dumps", flaky_dumps)
        with caplog.at_level("WARNING"):
            res = filter_terraform(inventory, contents, registry)
        assert res.filtered_files["bad.tf"] == contents["bad.tf"]
        assert 'resource "aws_kms_alias" "a"' in res.filtered_files["good.tf"]
        assert any("bad.tf" in r.message for r in caplog.records)
        assert "bad.tf" in res.prebuilt_inventory["unparsed_files"]
        assert "good.tf" not in res.prebuilt_inventory["unparsed_files"]

    def test_hash_scripts_matches_quoted_keys_in_object_literals(self, registry):
        # python-hcl2 8.x keeps object-literal keys quoted ('"user_data"'),
        # unlike ordinary attribute names -- the match must unquote first.
        contents = {
            "m.tf": (
                'resource "google_compute_instance" "w" {\n'
                '  machine_type = "e2-medium"\n'
                '  metadata     = { "user_data" = "echo RESOURCESECRET" }\n'
                "}\n"
                'data "template_file" "x" {\n'
                '  vars = { "template" = "echo DATASECRET" }\n'
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert "RESOURCESECRET" not in hcl
        assert "DATASECRET" not in hcl
        assert hcl.count("[script omitted: sha256:") == 2
        dumped = json.dumps(res.prebuilt_inventory)
        assert "RESOURCESECRET" not in dumped and "DATASECRET" not in dumped

    def test_hash_scripts_skips_dynamic_content_block_recurses_into_it(self, registry):
        # `dynamic "part" { content { ... } }` nests a real content BLOCK
        # under the key "content" -- which is also a hash-only name for data
        # blocks. Hashing the whole block would produce an invalid dynamic
        # block and lose content_type; it must recurse instead, hashing only
        # the innermost string attribute that's actually named "content".
        contents = {
            "m.tf": (
                'data "cloudinit_config" "y" {\n'
                '  dynamic "part" {\n'
                "    for_each = var.parts\n"
                "    content {\n"
                '      content_type = "text/x-shellscript"\n'
                '      content      = "echo PARTSECRET"\n'
                "    }\n"
                "  }\n"
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert "PARTSECRET" not in hcl
        assert "[script omitted: sha256:" in hcl
        assert "content_type" in hcl
        reparsed = hcl2.loads(hcl)
        part = reparsed["data"][0]['"cloudinit_config"']['"y"']["dynamic"][0]['"part"']
        assert isinstance(part["content"], list)  # still a block, not a string
        assert part["content"][0]["content_type"] == '"text/x-shellscript"'

    def test_http_request_body_is_hashed(self, registry):
        contents = {
            "m.tf": (
                'data "http" "x" {\n'
                '  url          = "https://example.com"\n'
                '  request_body = "echo HTTPSECRET"\n'
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert "HTTPSECRET" not in hcl
        assert "[script omitted: sha256:" in hcl

    def test_external_program_is_hashed(self, registry):
        contents = {
            "m.tf": (
                'data "external" "x" {\n  program = ["echo", "PROGRAMSECRET"]\n}\n'
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert "PROGRAMSECRET" not in hcl
        assert "[script omitted: sha256:" in hcl

    def test_variable_validation_counts_all_dropped_blocks(self, registry):
        contents = {
            "m.tf": (
                'variable "x" {\n'
                "  type = string\n"
                "  validation {\n"
                "    condition     = length(var.x) > 0\n"
                '    error_message = "must not be empty"\n'
                "  }\n"
                "  validation {\n"
                '    condition     = can(regex("^a", var.x))\n'
                '    error_message = "must start with a"\n'
                "  }\n"
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert "# 2 non-security attributes omitted" in hcl
        assert res.omitted_attributes == 2
        reparsed = hcl2.loads(hcl)  # must still be valid HCL
        assert "validation" not in json.dumps(reparsed)

    def test_validation_only_variable_renders_valid_hcl(self, registry):
        contents = {
            "m.tf": (
                'variable "x" {\n'
                "  validation {\n"
                "    condition     = true\n"
                '    error_message = "e"\n'
                "  }\n"
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert "# 1 non-security attributes omitted" in hcl
        reparsed = hcl2.loads(hcl)
        assert reparsed["variable"][0]['"x"']

    def test_module_content_and_template_not_hashed(self, registry):
        # data_hash_only_attrs applies only to data blocks -- module inputs
        # only ever get the general hash_only_attrs.
        contents = {
            "m.tf": (
                'module "m" {\n'
                '  source   = "../mod"\n'
                '  content  = "echo MODCONTENT"\n'
                '  template = "echo MODTEMPLATE"\n'
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert "echo MODCONTENT" in hcl
        assert "echo MODTEMPLATE" in hcl
        assert "[script omitted" not in hcl

    def test_module_input_scripts_are_hashed_everywhere(self, registry):
        contents = {
            "m.tf": (
                'module "m" {\n'
                '  source    = "../mod"\n'
                '  user_data = "#!/bin/bash\\necho MODSECRET"\n'
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        assert "MODSECRET" not in res.filtered_files["m.tf"]
        assert "[script omitted: sha256:" in res.filtered_files["m.tf"]
        mod = _component(res, "module.m")
        assert mod["configuration"]["inputs"]["user_data"].startswith(
            "[script omitted: sha256:"
        )
        assert "MODSECRET" not in json.dumps(res.prebuilt_inventory)


class TestPrebuiltInventory:
    def test_components_from_all_four_providers(self, registry):
        res = _run(registry, "aws.tf", "azure.tf", "gcp.tf", "oci.tf")
        comps = res.prebuilt_inventory["components"]
        ids = {c["id"] for c in comps}
        assert {
            "aws_instance.web",
            "azurerm_key_vault.main",
            "google_compute_firewall.allow_https",
            "oci_core_subnet.private",
            "data.aws_ami.ubuntu",
            "module.dns",
        } <= ids
        for c in comps:
            assert c["type"] in ALLOWED_CATEGORIES, c["id"]
            assert c["name"] is None and c["purpose"] is None
            assert isinstance(c["configuration"], dict)
            assert isinstance(c["references"], list)
        assert _component(res, "azurerm_key_vault.main")["type"] == "security_control"
        assert (
            _component(res, "azurerm_key_vault.main")["provider"] == "Microsoft Azure"
        )
        assert _component(res, "oci_core_subnet.private")["type"] == "network"
        assert _component(res, "google_service_account.app")["type"] == "identity"
        assert _component(res, "mycorp_widget.custom")["type"] == "other"
        assert _component(res, "mycorp_widget.custom")["configuration"] == {
            "size": 3,
            "color": "blue",
        }

    def test_component_configuration_and_references(self, registry):
        res = _run(registry, "aws.tf")
        web = _component(res, "aws_instance.web")
        assert web["resource_type"] == "aws_instance"
        assert web["file"] == "aws.tf"
        assert web["configuration"]["ami"] == "data.aws_ami.ubuntu.id"
        assert web["configuration"]["ebs_block_device"] == [{"encrypted": True}]
        assert "instance_type" not in web["configuration"]
        assert "lifecycle" not in web["configuration"]
        assert "depends_on" not in web["configuration"]
        assert web["references"] == [
            "aws_iam_role.web",
            "aws_security_group.web",
            "aws_subnet.private",
            "data.aws_ami.ubuntu",
        ]
        mod = _component(res, "module.dns")
        assert mod["resource_type"] == "module"
        assert mod["configuration"]["source"] == "../../modules/dns/aws"
        assert mod["configuration"]["inputs"]["vpc_id"] == "aws_vpc.main.id"
        assert mod["references"] == ["aws_vpc.main"]

    def test_modules(self, registry):
        # variables/outputs are dead weight nothing consumes (Task 4) -- only
        # modules and unparsed_files are kept alongside components.
        inv = _run(registry, "aws.tf").prebuilt_inventory
        assert inv["modules"] == [
            {"id": "module.dns", "source": "../../modules/dns/aws", "file": "aws.tf"}
        ]
        assert "variables" not in inv
        assert "outputs" not in inv

    def test_configuration_keeps_reference_not_in_registry_security_attrs(
        self, registry
    ):
        # kms_key_id isn't in aws_kms_alias's security_attrs ([name,
        # target_key_id]), but it's a reference and must survive _configuration.
        # Bug: _configuration used to receive already-cleaned attributes, where
        # find_references (which only matches "${...}") can never match.
        contents = {
            "m.tf": (
                'resource "aws_kms_alias" "a" {\n'
                '  name       = "alias/x"\n'
                "  kms_key_id = aws_kms_key.main.arn\n"
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        cfg = _component(res, "aws_kms_alias.a")["configuration"]
        assert cfg["kms_key_id"] == "aws_kms_key.main.arn"
        assert cfg["name"] == "alias/x"

    def test_prebuilt_inventory_is_json_serializable(self, registry):
        res = _run(registry, "aws.tf", "azure.tf", "gcp.tf", "oci.tf", "broken.tf")
        json.dumps(res.prebuilt_inventory)


class TestRealModule:
    """Static parse + filter over a copy of tmi/terraform/modules/network/aws."""

    def test_resource_count_matches_resource_blocks(self, registry):
        files = sorted((FIXTURES / "tmi_network_aws").glob("*.tf"))
        contents = {
            f"tmi_network_aws/{f.name}": f.read_text(encoding="utf-8") for f in files
        }
        expected = sum(len(RESOURCE_BLOCK_RE.findall(t)) for t in contents.values())
        assert expected > 20

        inv = parse_terraform(contents)
        assert inv.unparsed_files == []
        assert len(inv.resources) == expected

        res = filter_terraform(inv, contents, registry)
        resource_components = [
            c
            for c in res.prebuilt_inventory["components"]
            if not c["id"].startswith(("data.", "module."))
        ]
        assert len(resource_components) == expected
        assert all(
            c["type"] in ALLOWED_CATEGORIES
            for c in res.prebuilt_inventory["components"]
        )
        # every filtered file still parses, and the filter shrank the module
        for path, text in res.filtered_files.items():
            assert len(RESOURCE_BLOCK_RE.findall(text)) == len(
                RESOURCE_BLOCK_RE.findall(contents[path])
            ), path
        assert sum(map(len, res.filtered_files.values())) < sum(
            map(len, contents.values())
        )


from tmi_tf.tf_filter import display_name, merge_phase1


def _prebuilt() -> dict:
    return {
        "components": [
            {
                "id": "aws_instance.web_server",
                "resource_type": "aws_instance",
                "type": "compute",
                "provider": "AWS",
                "file": "main.tf",
                "configuration": {"ami": "ami-1"},
                "references": ["aws_subnet.private"],
                "name": None,
                "purpose": None,
            },
            {
                "id": "mycorp_widget.custom",
                "resource_type": "mycorp_widget",
                "type": "other",
                "provider": None,
                "file": "main.tf",
                "configuration": {"size": 3},
                "references": [],
                "name": None,
                "purpose": None,
            },
        ],
        "modules": [],
        "unparsed_files": [],
    }


class TestMergePhase1:
    def test_display_name(self):
        assert display_name("aws_instance.web_server") == "Web Server"
        assert display_name("data.aws_ami.ubuntu") == "Ubuntu (data)"
        assert display_name("module.dns") == "Dns (module)"
        assert display_name("weird") == "Weird"

    def test_merge_produces_current_schema(self):
        semantic = {
            "components": [
                {"id": "aws_instance.web_server", "name": "Web", "purpose": "Serves"},
                {
                    "id": "mycorp_widget.custom",
                    "name": "Widget",
                    "purpose": "?",
                    "type": "storage",
                },
                {"id": "aws_ghost.nope", "name": "Ghost", "purpose": "hallucinated"},
            ],
            "services": [
                {
                    "name": "web",
                    "criteria": ["naming"],
                    "compute_units": ["aws_instance.web_server"],
                    "associated_resources": [],
                }
            ],
            "dependencies": [
                {
                    "type": "cloud",
                    "provider": "AWS",
                    "service": "EC2",
                    "dependent_components": ["aws_instance.web_server"],
                }
            ],
        }
        merged = merge_phase1(_prebuilt(), semantic)
        assert set(merged) == {"components", "services", "dependencies"}
        assert [c["id"] for c in merged["components"]] == [
            "aws_instance.web_server",
            "mycorp_widget.custom",
        ]
        web = merged["components"][0]
        assert set(web) == {
            "id",
            "name",
            "type",
            "resource_type",
            "configuration",
            "purpose",
            "dependencies",
        }
        assert web["name"] == "Web"
        assert web["purpose"] == "Serves"
        assert web["type"] == "compute"
        assert web["configuration"] == {"ami": "ami-1"}
        assert web["dependencies"] == [
            {"type": "cloud", "provider": "AWS", "service": "EC2"}
        ]
        widget = merged["components"][1]
        assert widget["type"] == "storage"  # reclassified from other
        assert widget["dependencies"] == []
        assert merged["services"] == semantic["services"]
        assert merged["dependencies"] == semantic["dependencies"]

    def test_merge_only_reclassifies_other(self):
        semantic = {
            "components": [
                {
                    "id": "aws_instance.web_server",
                    "name": "W",
                    "purpose": "p",
                    "type": "storage",
                },
                {
                    "id": "mycorp_widget.custom",
                    "name": "X",
                    "purpose": "p",
                    "type": "bogus",
                },
            ]
        }
        merged = merge_phase1(_prebuilt(), semantic)
        assert merged["components"][0]["type"] == "compute"
        assert merged["components"][1]["type"] == "other"

    def test_merge_fills_missing_names(self):
        merged = merge_phase1(_prebuilt(), {})
        assert merged["components"][0]["name"] == "Web Server"
        assert merged["components"][0]["purpose"] == ""
        assert merged["services"] == [] and merged["dependencies"] == []

    def test_merge_tolerates_malformed_semantic_output(self):
        semantic = {
            "components": {"id": "aws_instance.web_server"},  # not a list
            "services": "none",
            "dependencies": [
                {
                    "type": "cloud",
                    "provider": "AWS",
                    "service": "EC2",
                    "dependent_components": "aws_instance.web_server",
                },
                "garbage",
                {
                    "type": "saas",
                    "provider": "GitHub",
                    "service": "Actions",
                    "dependent_components": ["aws_instance.web_server", 42],
                },
            ],
        }
        merged = merge_phase1(_prebuilt(), semantic)
        assert merged["components"][0]["name"] == "Web Server"
        assert merged["services"] == []
        assert merged["dependencies"] == [
            {
                "type": "cloud",
                "provider": "AWS",
                "service": "EC2",
                "dependent_components": ["aws_instance.web_server"],
            },
            {
                "type": "saas",
                "provider": "GitHub",
                "service": "Actions",
                "dependent_components": ["aws_instance.web_server"],
            },
        ]
        assert merged["components"][0]["dependencies"] == [
            {"type": "cloud", "provider": "AWS", "service": "EC2"},
            {"type": "saas", "provider": "GitHub", "service": "Actions"},
        ]

        # unhashable id in a components entry must not raise (TypeError in the
        # dict comprehension otherwise)
        merged2 = merge_phase1(
            _prebuilt(),
            {
                "components": [
                    {"id": ["not", "hashable"], "name": "N", "purpose": "P"},
                    {"id": "aws_instance.web_server", "name": "W2", "purpose": "P2"},
                ]
            },
        )
        assert merged2["components"][0]["name"] == "W2"

        # unhashable claimed type on an "other" component must not raise and
        # must not reclassify (TypeError from `in ALLOWED_CATEGORIES` otherwise)
        merged3 = merge_phase1(
            _prebuilt(),
            {
                "components": [
                    {"id": "mycorp_widget.custom", "name": "X", "type": ["storage"]},
                ]
            },
        )
        assert merged3["components"][1]["type"] == "other"

    def test_merge_keeps_duplicate_ids_both_get_semantics(self):
        """Two modules resolving to the same address (Review Focus 1) both keep
        their distinct static fields but share the LLM's one semantic entry."""
        prebuilt = {
            "components": [
                {
                    "id": "aws_iam_role.this",
                    "resource_type": "aws_iam_role",
                    "type": "identity",
                    "provider": "AWS",
                    "file": "modules/secrets/main.tf",
                    "configuration": {"name": "secrets-role"},
                    "references": [],
                    "name": None,
                    "purpose": None,
                },
                {
                    "id": "aws_iam_role.this",
                    "resource_type": "aws_iam_role",
                    "type": "identity",
                    "provider": "AWS",
                    "file": "modules/logging/main.tf",
                    "configuration": {"name": "logging-role"},
                    "references": [],
                    "name": None,
                    "purpose": None,
                },
            ],
            "modules": [],
            "unparsed_files": [],
        }
        semantic = {
            "components": [
                {"id": "aws_iam_role.this", "name": "Role", "purpose": "P"},
            ]
        }
        merged = merge_phase1(prebuilt, semantic)
        assert [(c["name"], c["purpose"]) for c in merged["components"]] == [
            ("Role", "P"),
            ("Role", "P"),
        ]
        # static per-occurrence fields are preserved independently
        assert [c["configuration"] for c in merged["components"]] == [
            {"name": "secrets-role"},
            {"name": "logging-role"},
        ]


class TestPromptInventory:
    """The compact inventory sent in the phase-1 PROMPT (Task 7): configuration,

    name, purpose, variables and outputs are dropped -- they're either
    duplicated in the filtered HCL or not yet known.
    """

    def test_keeps_only_six_component_keys(self):
        prebuilt = {
            "components": [
                {
                    "id": "aws_instance.web",
                    "resource_type": "aws_instance",
                    "type": "compute",
                    "provider": "AWS",
                    "file": "main.tf",
                    "configuration": {"ami": "ami-1"},
                    "references": ["aws_subnet.private"],
                    "name": None,
                    "purpose": None,
                }
            ],
            "modules": [{"id": "module.dns", "source": "x", "file": "main.tf"}],
            "unparsed_files": ["broken.tf"],
        }
        out = prompt_inventory(prebuilt)
        assert set(out) == {"components", "modules", "unparsed_files"}
        assert out["components"] == [
            {
                "id": "aws_instance.web",
                "resource_type": "aws_instance",
                "type": "compute",
                "provider": "AWS",
                "file": "main.tf",
                "references": ["aws_subnet.private"],
            }
        ]
        assert out["modules"] == prebuilt["modules"]
        assert out["unparsed_files"] == prebuilt["unparsed_files"]

    def test_omits_none_and_empty_list_values(self):
        prebuilt = {
            "components": [
                {
                    "id": "module.dns",
                    "resource_type": "module",
                    "type": "other",
                    "provider": None,
                    "file": "main.tf",
                    "configuration": {"source": "x"},
                    "references": [],
                    "name": None,
                    "purpose": None,
                }
            ],
            "modules": [],
            "unparsed_files": [],
        }
        out = prompt_inventory(prebuilt)
        assert out["components"] == [
            {
                "id": "module.dns",
                "resource_type": "module",
                "type": "other",
                "file": "main.tf",
            }
        ]

    def test_never_raises_on_sparse_prebuilt(self):
        assert prompt_inventory({}) == {
            "components": [],
            "modules": [],
            "unparsed_files": [],
        }
        assert prompt_inventory({"components": [{"id": "x"}]}) == {
            "components": [{"id": "x"}],
            "modules": [],
            "unparsed_files": [],
        }

    def test_prompt_inventory_json_is_compact(self):
        prebuilt = {
            "components": [
                {
                    "id": "aws_instance.web",
                    "resource_type": "aws_instance",
                    "type": "compute",
                    "file": "main.tf",
                }
            ],
            "modules": [],
            "unparsed_files": [],
        }
        text = prompt_inventory_json(prebuilt)
        assert "\n" not in text
        assert ", " not in text
        assert json.loads(text) == prompt_inventory(prebuilt)

    def test_real_module_prompt_inventory_has_no_configuration_key(self, registry):
        files = sorted((FIXTURES / "tmi_network_aws").glob("*.tf"))
        contents = {
            f"tmi_network_aws/{f.name}": f.read_text(encoding="utf-8") for f in files
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        text = prompt_inventory_json(res.prebuilt_inventory)
        assert '"configuration"' not in text
        assert '"name"' not in text
        assert '"purpose"' not in text


class TestWhitespaceNormalization:
    def test_no_whitespace_only_or_double_blank_lines_in_real_module(self, registry):
        files = sorted((FIXTURES / "tmi_network_aws").glob("*.tf"))
        contents = {
            f"tmi_network_aws/{f.name}": f.read_text(encoding="utf-8") for f in files
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        for path, text in res.filtered_files.items():
            lines = text.split("\n")
            assert not any(line != "" and line.strip() == "" for line in lines), (
                f"{path} has a whitespace-only line"
            )
            assert not any(a == "" and b == "" for a, b in itertools.pairwise(lines)), (
                f"{path} has a double blank line"
            )

    def test_heredoc_blank_lines_survive_normalization(self, registry):
        contents = {
            "m.tf": (
                'resource "aws_iam_role" "x" {\n'
                '  name = "x"\n'
                "  assume_role_policy = <<-EOT\n"
                "  {\n"
                '    "a": 1\n'
                "\n"
                "\n"
                '    "b": 2\n'
                "  }\n"
                "  EOT\n"
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert '"a": 1\n\n\n    "b": 2' in hcl, (
            "heredoc's own blank lines must be preserved byte-for-byte"
        )
