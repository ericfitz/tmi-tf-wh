"""Tests for registry-driven filtering and the pre-built inventory (issue #10)."""

import json
import re
from pathlib import Path

import pytest  # type: ignore

from tmi_tf.tf_filter import (
    ALLOWED_CATEGORIES,
    REGISTRY_PATH,
    FilterResult,
    Registry,
    filter_terraform,
    load_registry,
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

    def test_variables_outputs_modules(self, registry):
        inv = _run(registry, "aws.tf").prebuilt_inventory
        var = {v["name"]: v for v in inv["variables"]}
        assert var["region"] == {
            "name": "region",
            "type": "string",
            "default": "us-east-1",
            "description": "AWS region",
        }
        assert "default" not in var["db_password"]  # sensitive
        out = {o["name"]: o for o in inv["outputs"]}
        assert out["instance_ip"]["value"] == "aws_instance.web.private_ip"
        assert out["db_password"]["sensitive"] is True
        assert inv["modules"] == [
            {"id": "module.dns", "source": "../../modules/dns/aws", "file": "aws.tf"}
        ]

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
