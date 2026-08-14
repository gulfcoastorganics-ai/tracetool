"""Environment-specific assurance context."""

import platform
import sys

from .models import EnvironmentReport


def current_environment(*, implementation=None, generator_code_path=None, entropy_api=None, runtime=None):
    return EnvironmentReport(implementation=implementation, platform=platform.system().lower(), runtime=runtime or f"CPython {sys.version_info.major}.{sys.version_info.minor}", generator_code_path=generator_code_path, entropy_api=entropy_api, library_versions={"python": platform.python_version()}, notes=["Native Python and browser/WASM paths require separate audits."])


def environment_assurance(report: EnvironmentReport, audited: bool):
    return "STRONG_EVIDENCE" if audited and report.entropy_api else "PARTIAL_EVIDENCE" if audited else "INSUFFICIENT_EVIDENCE"
