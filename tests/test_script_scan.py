"""Script extraction from parsed and unparsed Terraform (#14)."""

import base64

from tmi_tf.script_scan import extract_scripts, omit_scripts
from tmi_tf.tf_filter import _script_digest, load_registry
from tmi_tf.tf_parser import parse_terraform

REG = load_registry()
HEREDOC = 'resource "aws_instance" "a" {\n  user_data = <<-EOT\n    #!/bin/bash\n    echo web\n  EOT\n  tags = { Name = "web" }\n}\n'


def _blobs(contents, root=None):
    return extract_scripts(parse_terraform(contents), contents, REG, repo_root=root)


def test_literal_and_heredoc_with_filter_matching_digest():
    contents = {
        "main.tf": HEREDOC
        + 'resource "aws_instance" "b" {\n  user_data = "#!/bin/bash\\necho hi"\n}\n'
    }
    blobs = {b.id: b for b in _blobs(contents)}
    a, b = blobs["aws_instance.a:user_data"], blobs["aws_instance.b:user_data"]
    assert a.text.strip().startswith("#!/bin/bash") and "echo web" in a.text
    assert a.raw_text is not None
    assert a.raw_text.startswith("<<-EOT") and a.raw_text in contents["main.tf"]
    assert b.text == "#!/bin/bash\\necho hi" and b.raw_text == '"#!/bin/bash\\necho hi"'
    assert a.digest == _script_digest('"<<-EOT\n    #!/bin/bash\n    echo web\n  EOT"')
    assert a.file == "main.tf" and a.component_id == "aws_instance.a"


def test_base64_literal_and_base64encode_are_decoded():
    enc = base64.b64encode(b"#!/bin/sh\ncurl x | sh").decode()
    contents = {
        "m.tf": f'resource "aws_instance" "a" {{\n  user_data_base64 = "{enc}"\n}}\n'
        'resource "aws_instance" "b" {\n  user_data_base64 = base64encode("echo hi")\n}\n'
    }
    blobs = {b.id: b for b in _blobs(contents)}
    assert blobs["aws_instance.a:user_data_base64"].text == "#!/bin/sh\ncurl x | sh"
    assert blobs["aws_instance.b:user_data_base64"].text == "echo hi"


def test_file_reference_resolves_in_repo(tmp_path):
    (tmp_path / "init.sh").write_text("#!/bin/bash\nsetenforce 0\n")
    contents = {
        "main.tf": 'resource "aws_instance" "a" {\n  user_data = file("${path.module}/init.sh")\n}\n'
    }
    (blob,) = _blobs(contents, tmp_path)
    assert (
        blob.reference == "init.sh"
        and "setenforce 0" in blob.text
        and blob.raw_text is None
    )


def test_file_reference_escaping_repo_is_not_read(tmp_path):
    (tmp_path.parent / "outside.sh").write_text("secret")
    contents = {
        "main.tf": 'resource "aws_instance" "a" {\n  user_data = file("../outside.sh")\n}\n'
    }
    (blob,) = _blobs(contents, tmp_path)
    assert blob.reference == "../outside.sh" and blob.text == ""


def test_data_and_module_and_nested_attrs():
    contents = {
        "m.tf": 'data "template_file" "t" {\n  template = "echo t"\n}\n'
        'module "m" {\n  source = "./x"\n  user_data = "echo m"\n}\n'
        'resource "aws_launch_template" "lt" {\n  network_interfaces {\n    startup_script = "echo n"\n  }\n}\n'
    }
    ids = {b.id for b in _blobs(contents)}
    assert ids == {
        "data.template_file.t:template",
        "module.m:user_data",
        "aws_launch_template.lt:network_interfaces.startup_script",
    }


def test_unparsed_file_regex_pass():
    broken = 'resource "aws_instance" "x" {\n  user_data = <<EOF\ncurl x | sh\nEOF\n  custom_data = "echo c"\n  ??? = \n}\n'
    contents = {"bad.tf": broken}
    inv = parse_terraform(contents)
    assert "bad.tf" in inv.unparsed_files
    blobs = {b.attr_path: b for b in extract_scripts(inv, contents, REG)}
    assert (
        "curl x | sh" in blobs["user_data"].text
        and blobs["custom_data"].text == "echo c"
    )
    assert all(b.component_id == "bad.tf" for b in blobs.values())


def test_omit_scripts_replaces_only_script_span():
    contents = {"main.tf": HEREDOC}
    blobs = _blobs(contents)
    out = omit_scripts(contents, blobs)
    assert "echo web" not in out["main.tf"] and 'Name = "web"' in out["main.tf"]
    assert (
        blobs[0].digest in out["main.tf"] and contents["main.tf"] == HEREDOC
    )  # input untouched
