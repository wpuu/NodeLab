"""Public output is an allowlist of validated scalars, never scrubbed input."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from nodelab.types import PROBE_GATE_OPEN, ParsedNode

_STATUS = frozenset({"PASS", "FAIL", "PARTIAL", "CONFLICT", "UNSUPPORTED"})
_STAGE = frozenset({
    "INPUT", "PARSE", "CONFIG", "BINARY", "STARTUP", "CONTROLLER",
    "ROUTE", "EXIT_A", "EXIT_B", "CLEANUP",
})
_PROTOCOL = frozenset({"vless", "trojan"})
_TRANSPORT = frozenset({"tcp", "ws", "grpc"})
_TLS_MODE = frozenset({"tls", "reality"})
_ERROR_CODE = frozenset({
    "INVALID_ARGUMENTS", "URI_ARGV_FORBIDDEN", "INPUT_FILE_UNSAFE", "INPUT_TOO_LARGE",
    "INVALID_UTF8", "INVALID_URI", "INVALID_PERCENT_ENCODING", "INVALID_HOST",
    "INVALID_HOST_HEADER", "INVALID_PORT", "INVALID_SECRET", "INVALID_PATH",
    "INVALID_SERVICE_NAME", "INVALID_QUERY", "INVALID_FLAG", "INVALID_ALPN",
    "LINE_TOO_LONG", "DUPLICATE_PARAM", "UNSUPPORTED_PROTOCOL",
    "UNSUPPORTED_QUERY_PARAM", "UNSUPPORTED_SECURITY", "UNSUPPORTED_TRANSPORT",
    "UNSUPPORTED_SNI_REQUIRED", "UNSUPPORTED_FLOW_COMBINATION", "UNSUPPORTED_FLOW",
    "UNSUPPORTED_ALPN", "UNSUPPORTED_FINGERPRINT", "UNSUPPORTED_REALITY",
    "UNSUPPORTED_HTTPUPGRADE", "UNSUPPORTED_ENCRYPTION",
    "PROBE_GATE_CLOSED", "ROUTE_PROOF_UNAVAILABLE", "ROUTE_DIRECT",
    "RUNTIME_MISMATCH", "PROBE_DEADLINE", "CONFIG_TEST_FAILED",
    "CONFIG_TEST_TIMEOUT", "CONFIG_BUILD_FAILED", "BINARY_MISMATCH",
    "PROCESS_START_FAILED", "PROCESS_STOP_FAILED", "PRIVATE_DIR_UNSAFE",
    "SECRET_CLEANUP_FAILED", "RECOVERY_REVIEW_REQUIRED",
    "UNSUPPORTED_INSECURE_NOT_APPROVED", "PUBLIC_SCHEMA_REJECTED",
})


def _enum(value: Any, allowed: frozenset[str]) -> str | None:
    return value if type(value) is str and value in allowed else None


def _boolean(value: Any) -> bool | None:
    return value if type(value) is bool else None


def _number(value: Any, *, lower: int, upper: int) -> int | None:
    return value if type(value) is int and lower <= value <= upper else None


def redacted_node_dict(node: ParsedNode) -> dict[str, Any]:
    """Minimal, fixed public view; no URI, fragment or arbitrary metadata."""
    return redacted_result_dict(node.public_dict())


def redacted_result_dict(result: Any) -> dict[str, Any] | list[dict[str, Any]]:
    """Reconstruct a public dict/list without copying unknown keys/strings.

    Anything that fails validation is replaced with a fixed value or null;
    attacker-controlled strings never enter even an error field.  This is
    also the serializer for CLI, exceptions and eventual result persistence.
    """
    if isinstance(result, (list, tuple)):
        return [redacted_result_dict(item) for item in result]
    if isinstance(result, ParsedNode):
        result = result.public_dict()
    if not isinstance(result, Mapping):
        result = {"probe_status": "FAIL", "stage": "INPUT", "error_code": "PUBLIC_SCHEMA_REJECTED"}

    code = result.get("error_code")
    if code is not None and _enum(code, _ERROR_CODE) is None:
        code = "PUBLIC_SCHEMA_REJECTED"
    status = _enum(result.get("probe_status"), _STATUS)
    # While the gate is closed there is NO trusted route-evidence producer:
    # even a caller-constructed result with route_verified=True must not
    # publish a positive verdict.  Verdict authority itself lives in probe.py;
    # this is only the last line of defence behind types.PROBE_GATE_OPEN.
    gated = not PROBE_GATE_OPEN and status in {"PASS", "PARTIAL", "CONFLICT"}
    if gated:
        status, code = "FAIL", "ROUTE_PROOF_UNAVAILABLE"

    return {
        "schema_version": 1,
        "line_number": _number(result.get("line_number"), lower=1, upper=1_000_000),
        "protocol": _enum(result.get("protocol"), _PROTOCOL),
        "transport": _enum(result.get("transport"), _TRANSPORT),
        "tls_mode": _enum(result.get("tls_mode"), _TLS_MODE),
        "probe_status": status,
        "stage": "ROUTE" if gated else _enum(result.get("stage"), _STAGE),
        "error_code": code,
        "config_ok": _boolean(result.get("config_ok")),
        "controller_ready": _boolean(result.get("controller_ready")),
        "listener_ready": _boolean(result.get("listener_ready")),
        "route_verified": False if gated else _boolean(result.get("route_verified")),
        "source_count": 0 if gated else _number(result.get("source_count"), lower=0, upper=2),
        "sources_agree": None if gated else _boolean(result.get("sources_agree")),
        "latency_ms": _number(result.get("latency_ms"), lower=0, upper=120_000),
    }


def redact_value(value: Any) -> Any:
    """Legacy entry point: never attempt best-effort regexp sanitization."""
    if isinstance(value, (Mapping, ParsedNode, list, tuple)):
        return redacted_result_dict(value)
    return None
