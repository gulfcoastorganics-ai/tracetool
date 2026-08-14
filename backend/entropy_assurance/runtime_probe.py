"""Bounded runtime CSPRNG probes; these verify API operation, not min-entropy."""

import secrets

from .models import CheckStatus, RuntimeProbeResult


def probe_python(requested_bytes: int = 32, *, environment: str = "python-native", runtime: str = "CPython") -> RuntimeProbeResult:
    try:
        sample = secrets.token_bytes(requested_bytes)
        ok = len(sample) == requested_bytes
        return RuntimeProbeResult(environment=environment, runtime=runtime, api_available=True, request_succeeded=ok, bytes_returned=len(sample), requested_bytes=requested_bytes, status=CheckStatus.PASS if ok else CheckStatus.FAIL, notes=["Probe is bounded and supplementary; it does not prove min-entropy."])
    except Exception as exc:
        return RuntimeProbeResult(environment=environment, runtime=runtime, api_available=True, request_succeeded=False, requested_bytes=requested_bytes, status=CheckStatus.FAIL, notes=[f"CSPRNG request failed: {type(exc).__name__}"])


def probe_environment(environment: str, runtime: str, api: str, requested_bytes: int = 32):
    if environment.lower().startswith("python") and api in ("secrets.token_bytes", "os.urandom"):
        return probe_python(requested_bytes, environment=environment, runtime=runtime)
    return RuntimeProbeResult(environment=environment, runtime=runtime, api_available=False, request_succeeded=False, requested_bytes=requested_bytes, status=CheckStatus.UNKNOWN, notes=["Browser/Node probes require an execution context supplied by that environment; static source evidence was not treated as a runtime probe."])
