"""Tests for static HCL parsing (issue #10)."""

from pathlib import Path

from tmi_tf.tf_parser import (
    StaticInventory,
    clean_value,
    find_references,
    parse_terraform,
    unquote_literal,
)

FIXTURES = Path(__file__).parent / "fixtures" / "tf"


def _load(*names: str) -> dict[str, str]:
    return {n: (FIXTURES / n).read_text(encoding="utf-8") for n in names}


class TestHelpers:
    def test_unquote_literal(self):
        assert unquote_literal('"ami-123"') == "ami-123"
        assert unquote_literal("number") == "number"
        assert unquote_literal('"') == '"'

    def test_clean_value_unwraps_expressions_and_drops_marker(self):
        raw = {
            "ami": '"x"',
            "subnet_id": "${aws_subnet.private.id}",
            "name": '"web-${var.env}"',
            "ebs": [{"encrypted": True, "__is_block__": True}],
            "__comments__": [{"value": "a comment"}],
            "__is_block__": True,
        }
        assert clean_value(raw) == {
            "ami": "x",
            "subnet_id": "aws_subnet.private.id",
            "name": "web-${var.env}",
            "ebs": [{"encrypted": True}],
        }

    def test_find_references(self):
        value = {
            "a": "${aws_subnet.private.id}",
            "b": ["${data.aws_ami.ubuntu.id}", "${module.net.vpc_id}"],
            "c": "${var.x}-${local.y}-${each.value}-${path.module}",
            "d": "${data.http.remote.body}",
            "e": '"literal_with.dot"',
            "self": "${aws_instance.web.id}",
        }
        assert find_references(value, exclude="aws_instance.web") == [
            "aws_subnet.private",
            "data.aws_ami.ubuntu",
            "data.http.remote",
            "module.net",
        ]

    def test_find_references_excludes_dynamic_iterator_value_key(self):
        # Finding 2: `dynamic "ebs_block_device" { ... ebs_block_device.value.name
        # ... }`-style iterator refs are phantoms, not resource addresses --
        # unless the address is a data./module. address, where a resource
        # legitimately named "value" or "key" is not a phantom.
        value = {
            "a": "${ebs_block_device.value.name}",
            "b": "${authorized_networks.value}",
            "c": "${cidr_blocks.key}",
            "d": "${module.value}",
            "e": "${data.aws_ip_ranges.value}",
        }
        assert find_references(value) == [
            "data.aws_ip_ranges.value",
            "module.value",
        ]

    def test_find_references_excludes_var_each_local_non_addresses(self):
        # Pin (Task 1 review gap): var./each./local. never look like addresses
        # since none matches the resource-type-with-underscore alternative.
        value = {
            "a": "${var.my_map.key}",
            "b": "${each.value.id}",
            "c": "${local.x.y}",
        }
        assert find_references(value) == []


class TestParseTerraform:
    def test_resources_and_addresses(self):
        inv = parse_terraform(_load("aws.tf"))
        assert isinstance(inv, StaticInventory)
        addresses = [r.address for r in inv.resources]
        assert addresses == [
            "aws_vpc.main",
            "aws_subnet.private",
            "aws_security_group.web",
            "aws_iam_role.web",
            "aws_instance.web",
            "aws_s3_bucket.logs",
            "mycorp_widget.custom",
        ]
        web = next(r for r in inv.resources if r.address == "aws_instance.web")
        assert web.resource_type == "aws_instance"
        assert web.local_name == "web"
        assert web.file == "aws.tf"
        assert web.attributes["instance_type"] == "t3.micro"
        assert web.attributes["ebs_block_device"] == [
            {"device_name": "/dev/sda1", "encrypted": True, "volume_size": 20}
        ]
        assert web.references == [
            "aws_iam_role.web",
            "aws_security_group.web",
            "aws_subnet.private",
            "data.aws_ami.ubuntu",
        ]
        assert inv.unparsed_files == []
        assert set(inv.parsed_files) == {"aws.tf"}

    def test_data_sources_variables_outputs_modules_providers(self):
        inv = parse_terraform(_load("aws.tf"))
        assert [d.address for d in inv.data_sources] == ["data.aws_ami.ubuntu"]
        assert inv.data_sources[0].data_type == "aws_ami"
        assert inv.data_sources[0].attributes["most_recent"] is True

        by_name = {v.name: v for v in inv.variables}
        assert by_name["region"].type_expr == "string"
        assert by_name["region"].default == "us-east-1"
        assert by_name["region"].description == "AWS region"
        assert by_name["region"].sensitive is False
        assert by_name["db_password"].sensitive is True

        outs = {o.name: o for o in inv.outputs}
        assert outs["instance_ip"].value_expr == "aws_instance.web.private_ip"
        assert outs["instance_ip"].sensitive is False
        assert outs["db_password"].sensitive is True

        assert len(inv.modules) == 1
        assert inv.modules[0].name == "dns"
        assert inv.modules[0].source == "../../modules/dns/aws"
        assert inv.modules[0].inputs == {
            "zone": "example.com",
            "vpc_id": "aws_vpc.main.id",
        }
        assert inv.modules[0].file == "aws.tf"

        assert len(inv.providers) == 1
        assert inv.providers[0].name == "aws"
        assert inv.providers[0].alias is None
        assert inv.providers[0].config == {"region": "var.region"}

    def test_unparsable_file_is_reported_not_fatal(self):
        inv = parse_terraform(_load("aws.tf", "broken.tf"))
        assert inv.unparsed_files == ["broken.tf"]
        assert len(inv.resources) == 7
        assert "broken.tf" not in inv.parsed_files

    def test_any_exception_from_hcl2_marks_file_unparsed(self, monkeypatch):
        import tmi_tf.tf_parser as mod

        def boom(_text):
            raise AttributeError(
                "'ConditionalRule' object has no attribute 'expression'"
            )

        monkeypatch.setattr(mod.hcl2, "loads", boom)
        inv = parse_terraform({"a.tf": 'resource "x_y" "z" {}'})
        assert inv.unparsed_files == ["a.tf"]
        assert inv.resources == []

    def test_empty_and_comment_only_files_parse_to_nothing(self):
        inv = parse_terraform({"empty.tf": "", "c.tf": "# nothing\n"})
        assert inv.unparsed_files == []
        assert inv.resources == [] and inv.data_sources == []
        assert set(inv.parsed_files) == {"empty.tf", "c.tf"}

    def test_tfvars_parses_without_blocks(self):
        inv = parse_terraform({"terraform.tfvars": 'region = "us-east-1"\n'})
        assert inv.resources == []
        assert inv.parsed_files["terraform.tfvars"] == {"region": '"us-east-1"'}

    def test_duplicate_addresses_across_files_are_both_kept(self):
        body = 'resource "aws_iam_role" "this" {\n  name = "r"\n}\n'
        inv = parse_terraform({"modules/a/main.tf": body, "modules/b/main.tf": body})
        assert [r.address for r in inv.resources] == [
            "aws_iam_role.this",
            "aws_iam_role.this",
        ]
        assert sorted(r.file for r in inv.resources) == [
            "modules/a/main.tf",
            "modules/b/main.tf",
        ]

    def test_provider_alias(self):
        inv = parse_terraform(
            {"p.tf": 'provider "aws" {\n  region = "us-west-2"\n  alias = "west"\n}\n'}
        )
        assert inv.providers[0].alias == "west"
        assert inv.providers[0].config == {"region": "us-west-2"}
