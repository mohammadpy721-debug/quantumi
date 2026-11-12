"""QuantumAI: AST-powered security audits and README generation for Python projects."""

from .core import (
    DEFAULT_MODEL,
    AuditReport,
    CodeAnalyzer,
    Finding,
    ModuleInfo,
    QuantumAIAuthError,
    QuantumAIError,
)
from .readme import ReadmeGenerator

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_MODEL",
    "AuditReport",
    "CodeAnalyzer",
    "Finding",
    "ModuleInfo",
    "QuantumAIAuthError",
    "QuantumAIError",
    "ReadmeGenerator",
    "__version__",
]
