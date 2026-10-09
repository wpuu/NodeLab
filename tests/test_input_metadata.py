"""Independent format provenance boundaries for the anonymous offline report.

Source: NodeLab's pinned fe8c1399af7485aff70ead0015b5ab6dd6441455
inventory schema and the previously validated explicit Base64 candidate.
All private-looking values below are synthetic .invalid canaries. Format
metadata records the caller's declared handling, never reconstructs source
content from the anonymous inventory, and never extends inventory schema v1.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from nodelab.inventory import (
    InventoryInputError,
    build_input_metadata,
    build_inventory,
    render_inventory_report,
)
from nodelab.offline_file import OfflineFileError, save_reports


SENTINEL = "synthetic-format-private-sentinel"
URI = (
    f"trojan://{SENTINEL}@{SENTINEL}.example.invalid:443?"
    f"security=tls&sni=cover.example.invalid#{SENTINEL}"
)
FORMAT_METADATA = {
    "uri_lines": {
        "input_format": "uri_lines", "line_number_basis": "source_text", "decoding_passes": 0,
    },
    "base64": {
        "input_format": "base64", "line_number_basis": "decoded_text", "decoding_passes": 1,
    },
    "not_recorded": {
        "input_format": "not_recorded", "line_number_basis": "parser_text", "decoding_passes": None,
    },
}
FORMAT_EXPLANATIONS = {
    "uri_lines": ("输入格式：逐行 URI 文本", "依据：源文本行", "外层解码次数：0"),
    "base64": ("输入格式：Base64 订阅文本", "依据：单次解码后的文本行", "外层解码次数：1"),
    "not_recorded": ("输入格式：未记录", "原始包装方式未知", "外层解码次数：未记录"),
}


class FormatSubclass(str):
    """Even a seemingly allowed value is not the exact public value type."""


class MustNotCoerce:
    def __str__(self) -> str:
        raise AssertionError("format must not be stringified")

    def __repr__(self) -> str:
        return "MustNotCoerce(<synthetic>)"


BAD_FORMATS = [
    None, True, False, 0, 1, 0.0, b"base64", bytearray(b"uri_lines"),
    [], {}, {"input_format": "base64"}, ("base64",), MustNotCoerce(),
    FormatSubclass("base64"), FormatSubclass("uri_lines"), FormatSubclass("not_recorded"),
    "", "auto", "BASE64", "Base64", "base64 ", " uri_lines", "uri_lines\n",
    "not-recorded", "not_recorded\x00", SENTINEL,
    f"{SENTINEL}://{SENTINEL}.example.invalid/private", "base64\n" + SENTINEL,
]


@pytest.mark.parametrize("input_format", list(FORMAT_METADATA))
def test_metadata_has_exact_associated_fields_and_value_types(input_format: str) -> None:
    metadata = build_input_metadata(input_format)
    assert metadata == FORMAT_METADATA[input_format]
    assert type(metadata) is dict
    assert set(metadata) == {"input_format", "line_number_basis", "decoding_passes"}
    assert type(metadata["input_format"]) is str
    assert type(metadata["line_number_basis"]) is str
    if input_format == "not_recorded":
        assert metadata["decoding_passes"] is None
    else:
        assert type(metadata["decoding_passes"]) is int


def test_metadata_default_is_unknown_and_returned_dicts_are_independent() -> None:
    assert build_input_metadata() == FORMAT_METADATA["not_recorded"]
    first = build_input_metadata("base64")
    first["line_number_basis"] = SENTINEL
    first["input_format"] = SENTINEL
    first["decoding_passes"] = 0
    assert build_input_metadata("base64") == FORMAT_METADATA["base64"]
    assert build_input_metadata() == FORMAT_METADATA["not_recorded"]


@pytest.mark.parametrize("input_format", BAD_FORMATS)
def test_metadata_rejects_nonexact_format_with_fixed_error(input_format) -> None:
    with pytest.raises(InventoryInputError) as raised:
        build_input_metadata(input_format)
    assert raised.value.code == "INVALID_ARGUMENTS"
    assert str(raised.value) == "INVALID_ARGUMENTS"
    assert raised.value.args == ("INVALID_ARGUMENTS",)
    assert SENTINEL not in repr(raised.value)


def test_renderer_default_is_explicit_unknown_and_does_not_infer_from_report() -> None:
    report = build_inventory(URI)
    assert render_inventory_report(report) == render_inventory_report(report, input_format="not_recorded")
    default = render_inventory_report(report)
    for explanation in FORMAT_EXPLANATIONS["not_recorded"]:
        assert explanation in default
    assert "输入格式：Base64" not in default
    assert "输入格式：逐行 URI" not in default


@pytest.mark.parametrize("input_format", list(FORMAT_METADATA))
def test_renderer_declares_selected_format_and_line_basis_without_changing_v1_inventory(input_format: str) -> None:
    payload = URI.encode() + b"\n\n\xff\n" + URI.encode() + b"\n"
    report = build_inventory(payload)
    before = copy.deepcopy(report)
    serialized = json.dumps(report, sort_keys=True)
    markdown = render_inventory_report(report, input_format=input_format)
    for explanation in FORMAT_EXPLANATIONS[input_format]:
        assert explanation in markdown
    assert report == before
    assert json.dumps(report, sort_keys=True) == serialized
    assert report["schema_version"] == 1
    assert set(report).isdisjoint(FORMAT_METADATA[input_format])
    assert report["summary"]["physical_lines"] == 4
    assert [row["line_number"] for row in report["records"]] == [1, 3, 4]
    for record_id, line_number in [("R000001", 1), ("R000002", 3), ("R000003", 4)]:
        assert f"| {record_id} | {line_number} |" in markdown
    assert report["records"][1]["error_code"] == "INVALID_UTF8"
    assert report["records"][2]["duplicate_of"] == "R000001"
    assert report["network_used"] is False


def test_format_changes_explanation_but_preserves_all_record_rows() -> None:
    report = build_inventory((URI + "\n\n" + URI).encode())
    variants = [render_inventory_report(report, input_format=value) for value in FORMAT_METADATA]
    row_groups = [[line for line in output.splitlines() if line.startswith("| R")] for output in variants]
    assert row_groups[0] == row_groups[1] == row_groups[2]
    assert len(set(variants)) == 3


@pytest.mark.parametrize("input_format", BAD_FORMATS)
def test_renderer_rejects_invalid_format_without_exposing_value(input_format) -> None:
    with pytest.raises(InventoryInputError) as raised:
        render_inventory_report(build_inventory(URI), input_format=input_format)
    assert raised.value.code == "INVALID_ARGUMENTS"
    assert str(raised.value) == "INVALID_ARGUMENTS"
    assert raised.value.args == ("INVALID_ARGUMENTS",)
    assert SENTINEL not in repr(raised.value)


@pytest.mark.parametrize("input_format", BAD_FORMATS)
def test_save_rejects_invalid_format_before_any_path_io(
    input_format, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = build_inventory(URI)
    destination = tmp_path / "must-not-create"
    calls: list[str] = []

    def blocked(*args, **kwargs):
        calls.append("path IO")
        raise AssertionError("invalid format reached filesystem operation")

    # Creating tmp_path/report precedes the patch. The save call must reject
    # even before testing whether the destination exists or is local.
    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", blocked)
        patch.setattr(Path, "stat", blocked)
        patch.setattr(Path, "mkdir", blocked)
        patch.setattr(Path, "open", blocked)
        with pytest.raises(OfflineFileError) as raised:
            save_reports(report, destination, input_format=input_format)
    assert raised.value.code == "INVALID_ARGUMENTS"
    assert str(raised.value) == "INVALID_ARGUMENTS"
    assert raised.value.args == ("INVALID_ARGUMENTS",)
    assert calls == []
    assert not destination.exists()


def test_public_mapping_markdown_and_errors_never_echo_private_canary(capsys: pytest.CaptureFixture) -> None:
    report = build_inventory(URI)
    outputs = [json.dumps(report), repr(report)]
    for input_format in FORMAT_METADATA:
        outputs.extend([
            json.dumps(build_input_metadata(input_format)),
            render_inventory_report(report, input_format=input_format),
        ])
    with pytest.raises(InventoryInputError) as raised:
        build_input_metadata(SENTINEL)
    outputs.extend([str(raised.value), repr(raised.value), repr(raised.value.args)])
    captured = capsys.readouterr()
    outputs.extend([captured.out, captured.err])
    public = "\n".join(outputs)
    for private in [SENTINEL, URI, "cover.example.invalid", "trojan://"]:
        assert private not in public
    assert captured.out == captured.err == ""
