"""Supply Chain Security / SBOM Module

Provides comprehensive supply chain risk management, SBOM generation/parsing,
dependency analysis, and vendor assessment capabilities for PySOAR.
"""

from src.supplychain.models import (
    SoftwareComponent,
    SBOM,
    SBOMComponent,
    SupplyChainRisk,
    VendorAssessment,
)
from src.supplychain.engine import (
    SBOMGenerator,
    DependencyScanner,
    SupplyChainRiskAnalyzer,
    VendorRiskManager,
    CISASBOMCompliance,
)
from src.supplychain.tasks import (
    scheduled_dependency_scan,
    vulnerability_cross_reference,
    vendor_certification_expiry_check,
    sbom_regeneration,
    typosquatting_scan,
)

__all__ = [
    "SoftwareComponent",
    "SBOM",
    "SBOMComponent",
    "SupplyChainRisk",
    "VendorAssessment",
    "SBOMGenerator",
    "DependencyScanner",
    "SupplyChainRiskAnalyzer",
    "VendorRiskManager",
    "CISASBOMCompliance",
    "scheduled_dependency_scan",
    "vulnerability_cross_reference",
    "vendor_certification_expiry_check",
    "sbom_regeneration",
    "typosquatting_scan",
]
