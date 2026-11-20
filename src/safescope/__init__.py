"""SafeScope - a safe, non-intrusive web security posture scanner."""

from safescope._version import __version__
from safescope.models import Finding, ScanResult, Severity, Status
from safescope.scanner import Scanner, scan

__all__ = ["Finding", "ScanResult", "Scanner", "Severity", "Status", "scan", "__version__"]
