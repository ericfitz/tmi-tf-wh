"""Script extraction from parsed and unparsed Terraform (#14)."""

import base64
import logging
import time

from tmi_tf.script_scan import ScriptBlob, extract_scripts, omit_scripts, unomitted
from tmi_tf.tf_filter import _script_digest, load_registry
from tmi_tf.tf_parser import StaticInventory, parse_terraform

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


# --- review fixes: anchored omission, non-string values, path.root/cwd, linear scan ---


def test_omit_scripts_does_not_touch_identical_value_elsewhere():
    contents = {
        "main.tf": 'resource "aws_instance" "a" {\n'
        '  user_data = "echo dup"\n'
        '  tags = { Name = "echo dup" }\n'
        "}\n"
    }
    blobs = _blobs(contents)
    out = omit_scripts(contents, blobs)
    assert out["main.tf"].count('"echo dup"') == 1
    assert 'tags = { Name = "echo dup" }' in out["main.tf"]
    assert blobs[0].digest in out["main.tf"]


def test_omit_scripts_unparsed_anchors_to_attr_name():
    broken = (
        'resource "aws_instance" "x" {\n'
        '  custom_data = "echo dup"\n'
        '  description = "echo dup"\n'
        "  ??? = \n"
        "}\n"
    )
    contents = {"bad.tf": broken}
    inv = parse_terraform(contents)
    blobs = extract_scripts(inv, contents, REG)
    out = omit_scripts(contents, blobs)
    assert 'description = "echo dup"' in out["bad.tf"]
    assert out["bad.tf"].count('"echo dup"') == 1


def test_omit_scripts_replaces_each_duplicate_occurrence():
    contents = {
        "main.tf": 'resource "aws_instance" "a" {\n  user_data = "echo dup"\n}\n'
        'resource "aws_instance" "b" {\n  user_data = "echo dup"\n}\n'
    }
    blobs = _blobs(contents)
    out = omit_scripts(contents, blobs)
    assert out["main.tf"].count('"echo dup"') == 0
    assert out["main.tf"].count(blobs[0].digest) == 2


def test_omit_scripts_handles_quoted_attribute_key():
    contents = {
        "main.tf": 'resource "google_compute_instance" "a" {\n'
        "  metadata = {\n"
        '    "user_data" = "echo q"\n'
        "  }\n"
        "}\n"
    }
    blobs = _blobs(contents)
    out = omit_scripts(contents, blobs)
    assert "echo q" not in out["main.tf"]
    assert blobs[0].digest in out["main.tf"]


def test_list_and_object_user_data_match_filter_digest_and_extract_text():
    contents = {
        "main.tf": 'resource "aws_instance" "a" {\n  user_data = ["curl x | sh"]\n}\n'
        'resource "aws_instance" "b" {\n  user_data = { cmd = "curl y | sh" }\n}\n'
    }
    inv = parse_terraform(contents)
    blobs = {b.id: b for b in extract_scripts(inv, contents, REG)}
    a = blobs["aws_instance.a:user_data"]
    b = blobs["aws_instance.b:user_data"]
    assert "curl x | sh" in a.text and a.raw_text is None
    assert "curl y | sh" in b.text and b.raw_text is None
    raw_a = next(
        r for r in inv.resources if r.address == "aws_instance.a"
    ).raw_attributes["user_data"]
    raw_b = next(
        r for r in inv.resources if r.address == "aws_instance.b"
    ).raw_attributes["user_data"]
    assert a.digest == _script_digest(raw_a)
    assert b.digest == _script_digest(raw_b)


def test_path_root_and_cwd_resolve_from_repo_root(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "init.sh").write_text("#!/bin/bash\nsetenforce 0\n")
    for kind in ("root", "cwd"):
        contents = {
            "envs/prod/main.tf": 'resource "aws_instance" "a" {\n'
            f'  user_data = file("${{path.{kind}}}/scripts/init.sh")\n'
            "}\n"
        }
        (blob,) = extract_scripts(
            parse_terraform(contents), contents, REG, repo_root=tmp_path
        )
        assert blob.reference == "scripts/init.sh"
        assert "setenforce 0" in blob.text


def test_path_module_still_resolves_relative_to_file_dir(tmp_path):
    (tmp_path / "envs" / "prod").mkdir(parents=True)
    (tmp_path / "envs" / "prod" / "init.sh").write_text("#!/bin/bash\nsetenforce 0\n")
    contents = {
        "envs/prod/main.tf": 'resource "aws_instance" "a" {\n'
        '  user_data = file("${path.module}/init.sh")\n'
        "}\n"
    }
    (blob,) = extract_scripts(
        parse_terraform(contents), contents, REG, repo_root=tmp_path
    )
    assert blob.reference == "init.sh" and "setenforce 0" in blob.text


def test_unparsed_heredoc_scan_is_linear_time():
    # 1MB+ of back-to-back unterminated `<<X` starts: the old backtracking
    # regex re-scanned to EOF for every start line (quadratic); the fix scans
    # the file once.
    line = "user_data = <<EOF\n"
    big_text = line * 60000  # ~1.1MB
    inv = StaticInventory(unparsed_files=["big.tf"])
    start = time.perf_counter()
    extract_scripts(inv, {"big.tf": big_text}, REG)
    assert time.perf_counter() - start < 2.0


# --- re-review fixes: linear literal scan, exact heredoc spans, miss detection ---


def test_unparsed_literal_scan_is_linear_time():
    # 40k+ whitespace-only lines: the old `^\s*` (under MULTILINE, matching
    # newlines too) re-scanned forward through every following blank line
    # from each line start (quadratic). A few real assignments are mixed in
    # to confirm the fast path still extracts correctly; the trailing blank
    # block (nothing valid after it) is what actually forces the old regex's
    # worst case -- a leading/middle blank run before a real assignment lets
    # a single greedy sweep "rescue" it in one shot.
    blank = "   \n" * 40000
    text = 'custom_data = "echo c"\n' + blank + 'user_data = "echo u"\n' + blank
    inv = StaticInventory(unparsed_files=["big.tf"])
    start = time.perf_counter()
    blobs = {b.attr_path: b for b in extract_scripts(inv, {"big.tf": text}, REG)}
    assert time.perf_counter() - start < 2.0
    assert blobs["custom_data"].text == "echo c"
    assert blobs["user_data"].text == "echo u"


def test_unparsed_heredoc_open_line_trailing_whitespace_is_omitted():
    # A heredoc opener with trailing whitespace after the marker (hcl2 itself
    # rejects this syntax, so it always lands in the unparsed-fallback path).
    # The exact opening-line text (trailing spaces included) must be captured
    # so `omit_scripts`'s anchor can find and replace the whole span.
    broken = 'resource "aws_instance" "a" {\n  user_data = <<-EOT  \n    echo a\n  EOT\n  ??? =\n}\n'
    contents = {"bad.tf": broken}
    inv = parse_terraform(contents)
    assert "bad.tf" in inv.unparsed_files
    blobs = extract_scripts(inv, contents, REG)
    out = omit_scripts(contents, blobs)
    assert "echo a" not in out["bad.tf"]
    assert not unomitted(contents, blobs)


def test_unparsed_literal_inside_heredoc_body_is_not_a_separate_blob(caplog):
    # A line shaped like `attr = "..."` living *inside* another script's
    # heredoc body must not be mistaken for its own assignment (during
    # extraction) or trigger a false "not found" miss (during omission).
    broken = (
        'resource "aws_instance" "x" {\n'
        "  custom_data = <<EOF\n"
        '  user_data = "inner"\n'
        "EOF\n"
        "  ??? =\n"
        "}\n"
    )
    contents = {"bad.tf": broken}
    inv = parse_terraform(contents)
    assert "bad.tf" in inv.unparsed_files
    blobs = extract_scripts(inv, contents, REG)
    assert {b.attr_path for b in blobs} == {"custom_data"}
    with caplog.at_level(logging.WARNING, logger="tmi_tf.script_scan"):
        omit_scripts(contents, blobs)
    assert not unomitted(contents, blobs)
    assert not any("not found" in r.getMessage() for r in caplog.records)


def test_omit_scripts_is_linear_in_file_size_not_blob_count():
    # The old implementation ran one anchored `search`-from-offset-0 per
    # blob -- O(blobs * file size). 20k blobs in one file must stay fast.
    n = 20000
    text = "".join(f'custom_data = "x{i}"\n' for i in range(n))
    inv = StaticInventory(unparsed_files=["big.tf"])
    contents = {"big.tf": text}
    blobs = extract_scripts(inv, contents, REG)
    assert len(blobs) == n
    start = time.perf_counter()
    out = omit_scripts(contents, blobs)
    assert time.perf_counter() - start < 2.0
    assert not unomitted(contents, blobs)
    assert 'x0"' not in out["big.tf"]
    assert f'x{n - 1}"' not in out["big.tf"]


def test_omit_scripts_scales_to_50k_blobs_one_mb_file():
    n = 50000  # ~1MB
    text = "".join(f'custom_data = "y{i}"\n' for i in range(n))
    inv = StaticInventory(unparsed_files=["big.tf"])
    contents = {"big.tf": text}
    blobs = extract_scripts(inv, contents, REG)
    assert len(blobs) == n
    start = time.perf_counter()
    omit_scripts(contents, blobs)
    assert time.perf_counter() - start < 2.0


def test_omit_scripts_heredoc_shape_is_also_linear():
    n = 5000
    text = "".join(f"custom_data = <<EOF{i}\necho {i}\nEOF{i}\n" for i in range(n))
    inv = StaticInventory(unparsed_files=["big.tf"])
    contents = {"big.tf": text}
    blobs = extract_scripts(inv, contents, REG)
    assert len(blobs) == n
    start = time.perf_counter()
    out = omit_scripts(contents, blobs)
    assert time.perf_counter() - start < 2.0
    assert not unomitted(contents, blobs)
    assert "echo 0" not in out["big.tf"]


def test_omit_scripts_warns_and_reports_a_miss(caplog):
    # A blob whose raw_text span genuinely isn't in the file (e.g. produced
    # against a different snapshot of the source) must not fail silently.
    blob = ScriptBlob(
        "aws_instance.x:user_data",
        "aws_instance.x",
        "user_data",
        "main.tf",
        _script_digest('"missing"'),
        "missing",
        '"missing"',
    )
    contents = {"main.tf": 'resource "aws_instance" "x" {\n  other = "value"\n}\n'}
    with caplog.at_level(logging.WARNING, logger="tmi_tf.script_scan"):
        out = omit_scripts(contents, [blob])
    assert out["main.tf"] == contents["main.tf"]
    assert unomitted(contents, [blob]) == [blob]
    messages = [r.getMessage() for r in caplog.records]
    assert any("aws_instance.x:user_data" in m for m in messages)
    assert all("missing" not in m for m in messages)  # never log script text


def test_omit_scripts_handles_inline_object_keys(caplog):
    contents = {
        "main.tf": 'resource "google_compute_instance" "g" {\n'
        '  metadata = { "startup-script" = "curl a | sh", foo = "x" }\n}\n'
        'resource "aws_instance" "a" {\n  tags = { "user_data" = "curl b | sh" }\n}\n'
    }
    blobs = _blobs(contents)
    assert {b.id for b in blobs} == {
        "google_compute_instance.g:metadata.startup-script",
        "aws_instance.a:tags.user_data",
    }
    with caplog.at_level(logging.WARNING, logger="tmi_tf.script_scan"):
        out = omit_scripts(contents, blobs)["main.tf"]
    assert "curl a" not in out and "curl b" not in out
    assert 'foo = "x" }' in out
    assert not unomitted(contents, blobs) and not caplog.records


def test_omit_scripts_inline_object_shape_is_linear():
    n = 20000
    text = "".join(f'tags = {{ "user_data" = "x{i}", foo = "y" }}\n' for i in range(n))
    blobs = [
        ScriptBlob(
            f"r{i}:tags.user_data",
            f"r{i}",
            "tags.user_data",
            "big.tf",
            _script_digest(f'"x{i}"'),
            f"x{i}",
            f'"x{i}"',
        )
        for i in range(n)
    ]
    contents = {"big.tf": text}
    start = time.perf_counter()
    out = omit_scripts(contents, blobs)
    assert time.perf_counter() - start < 2.0
    assert not unomitted(contents, blobs)
    assert '"x0"' not in out["big.tf"] and out["big.tf"].count('foo = "y"') == n
    # ~1MB single line of unterminated inline assignments: still linear.
    start = time.perf_counter()
    omit_scripts({"big.tf": '{ user_data = "' * 70000}, blobs[:1])
    assert time.perf_counter() - start < 2.0
