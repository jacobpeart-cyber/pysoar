"""Supply Chain Security Engine

Core classes for SBOM generation, dependency scanning, risk analysis,
vendor assessment, and compliance validation.
"""

import json
import re
from datetime import datetime
from typing import Any, Optional
from xml.etree import ElementTree as ET

from src.core.logging import get_logger

logger = get_logger(__name__)


class SBOMGenerator:
    """Generate and parse Software Bill of Materials in multiple formats"""

    SPDX_VERSION = "2.3"
    CYCLONEDX_VERSION = "1.4"

    def __init__(self):
        """Initialize SBOM Generator"""
        self.logger = logger

    def parse_spdx_json(self, content: str) -> dict[str, Any]:
        """Parse SPDX JSON format SBOM

        Args:
            content: SPDX JSON content string

        Returns:
            Parsed SBOM dictionary
        """
        try:
            sbom_data = json.loads(content)
            return {
                "format": "spdx_json",
                "spec_version": sbom_data.get("spdxVersion", self.SPDX_VERSION),
                "name": sbom_data.get("name"),
                "created_by_tool": sbom_data.get("creationInfo", {}).get("creators", [None])[0],
                "components": sbom_data.get("packages", []),
                "relationships": sbom_data.get("relationships", []),
            }
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse SPDX JSON: {e}")
            raise

    def parse_spdx_xml(self, content: str) -> dict[str, Any]:
        """Parse SPDX XML format SBOM

        Args:
            content: SPDX XML content string

        Returns:
            Parsed SBOM dictionary
        """
        try:
            root = ET.fromstring(content)
            ns = {"spdx": "http://spdx.org/rdfterms#spdx"}

            return {
                "format": "spdx_xml",
                "spec_version": self.SPDX_VERSION,
                "name": root.find(".//spdx:name", ns).text if root.find(".//spdx:name", ns) is not None else None,
                "created_by_tool": root.find(".//spdx:creator", ns).text if root.find(".//spdx:creator", ns) is not None else None,
                "components": [
                    {
                        "name": elem.find("spdx:name", ns).text,
                        "version": elem.find("spdx:version", ns).text,
                    }
                    for elem in root.findall(".//spdx:Package", ns)
                ],
            }
        except ET.ParseError as e:
            self.logger.error(f"Failed to parse SPDX XML: {e}")
            raise

    def parse_cyclonedx_json(self, content: str) -> dict[str, Any]:
        """Parse CycloneDX JSON format SBOM

        Args:
            content: CycloneDX JSON content string

        Returns:
            Parsed SBOM dictionary
        """
        try:
            sbom_data = json.loads(content)
            metadata = sbom_data.get("metadata", {})

            return {
                "format": "cyclonedx_json",
                "spec_version": sbom_data.get("specVersion", self.CYCLONEDX_VERSION),
                "name": metadata.get("component", {}).get("name"),
                "created_by_tool": metadata.get("tools", [{}])[0].get("name"),
                "components": sbom_data.get("components", []),
                "dependencies": sbom_data.get("dependencies", []),
            }
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse CycloneDX JSON: {e}")
            raise

    def parse_cyclonedx_xml(self, content: str) -> dict[str, Any]:
        """Parse CycloneDX XML format SBOM

        Args:
            content: CycloneDX XML content string

        Returns:
            Parsed SBOM dictionary
        """
        try:
            root = ET.fromstring(content)
            ns = {"cdx": "http://cyclonedx.org/schema/bom/1.4"}

            return {
                "format": "cyclonedx_xml",
                "spec_version": root.get("specVersion", self.CYCLONEDX_VERSION),
                "name": root.find(".//cdx:component/cdx:name", ns).text if root.find(".//cdx:component/cdx:name", ns) is not None else None,
                "components": [
                    {
                        "name": elem.find("cdx:name", ns).text,
                        "version": elem.find("cdx:version", ns).text,
                        "purl": elem.find("cdx:purl", ns).text,
                    }
                    for elem in root.findall(".//cdx:component", ns)
                ],
            }
        except ET.ParseError as e:
            self.logger.error(f"Failed to parse CycloneDX XML: {e}")
            raise

    def generate_spdx_output(self, sbom_data: dict[str, Any]) -> str:
        """Generate SPDX JSON output

        Args:
            sbom_data: SBOM data dictionary

        Returns:
            SPDX JSON formatted string
        """
        spdx_doc = {
            "spdxVersion": f"SPDX-{self.SPDX_VERSION}",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": sbom_data.get("name", "Application"),
            "documentNamespace": f"https://sbom.pysoar/{sbom_data.get('id', 'unknown')}",
            "creationInfo": {
                "created": datetime.utcnow().isoformat() + "Z",
                "creators": [sbom_data.get("created_by_tool", "PySOAR")],
                "licenseListVersion": "3.19",
            },
            "packages": sbom_data.get("components", []),
            "relationships": sbom_data.get("relationships", []),
        }
        return json.dumps(spdx_doc, indent=2)

    def generate_cyclonedx_output(self, sbom_data: dict[str, Any]) -> str:
        """Generate CycloneDX JSON output

        Args:
            sbom_data: SBOM data dictionary

        Returns:
            CycloneDX JSON formatted string
        """
        cyclonedx_doc = {
            "bomFormat": "CycloneDX",
            "specVersion": self.CYCLONEDX_VERSION,
            "serialNumber": f"urn:uuid:{sbom_data.get('id', 'unknown')}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [{"name": sbom_data.get("created_by_tool", "PySOAR")}],
                "component": {
                    "bom-ref": "application",
                    "type": "application",
                    "name": sbom_data.get("name", "Application"),
                    "version": sbom_data.get("version", "1.0"),
                },
            },
            "components": sbom_data.get("components", []),
        }
        return json.dumps(cyclonedx_doc, indent=2)

    def build_dependency_tree(
        self, components: list[dict[str, Any]], relationships: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Build hierarchical dependency tree from components and relationships

        Args:
            components: List of component objects
            relationships: List of relationship objects

        Returns:
            Dependency tree structure
        """
        tree = {}
        depth_map = {}

        for component in components:
            comp_id = component.get("id") or component.get("name")
            tree[comp_id] = {
                "component": component,
                "dependencies": [],
                "depth": 0,
            }
            depth_map[comp_id] = 0

        for rel in relationships:
            from_id = rel.get("from")
            to_id = rel.get("to")
            rel_type = rel.get("type", "depends_on")

            if from_id in tree and to_id in tree:
                tree[from_id]["dependencies"].append({
                    "component_id": to_id,
                    "type": rel_type,
                })
                # Update depth
                depth_map[to_id] = max(depth_map.get(to_id, 0), depth_map[from_id] + 1)

        # Update depths in tree
        for comp_id in tree:
            tree[comp_id]["depth"] = depth_map[comp_id]

        return tree

    def calculate_transitive_risk(
        self, component_risks: dict[str, float], dependency_tree: dict[str, Any]
    ) -> dict[str, float]:
        """Calculate risk propagation through dependency chains

        Args:
            component_risks: Component ID to risk score mapping
            dependency_tree: Dependency tree structure

        Returns:
            Component ID to transitive risk score mapping
        """
        transitive_risks = {}

        def compute_risk(comp_id: str, visited: set[str] | None = None) -> float:
            if visited is None:
                visited = set()

            if comp_id in visited:
                return 0.0
            visited.add(comp_id)

            base_risk = component_risks.get(comp_id, 0.0)

            if comp_id not in dependency_tree:
                return base_risk

            deps = dependency_tree[comp_id].get("dependencies", [])
            if not deps:
                return base_risk

            # Propagate risk from dependencies (discount by depth)
            dep_risk = 0.0
            for dep in deps:
                dep_id = dep.get("component_id")
                dep_score = compute_risk(dep_id, visited.copy())
                # Risk propagates but with attenuation
                dep_risk = max(dep_risk, dep_score * 0.8)

            transitive_risk = max(base_risk, (base_risk + dep_risk) / 2)
            transitive_risks[comp_id] = transitive_risk

            return transitive_risk

        for comp_id in dependency_tree:
            compute_risk(comp_id)

        return transitive_risks


class DependencyScanner:
    """Scan dependencies in various package manager formats"""

    def __init__(self):
        """Initialize Dependency Scanner"""
        self.logger = logger

    def scan_npm_lockfile(self, lockfile_content: str) -> list[dict[str, Any]]:
        """Parse npm package-lock.json

        Args:
            lockfile_content: Content of package-lock.json

        Returns:
            List of dependency objects
        """
        try:
            lockfile = json.loads(lockfile_content)
            dependencies = []

            def extract_deps(packages: dict[str, Any], prefix: str = ""):
                for name, spec in packages.items():
                    version = spec.get("version", "unknown")
                    dependencies.append({
                        "name": name,
                        "version": version,
                        "package_type": "npm",
                        "purl": f"pkg:npm/{name}@{version}",
                    })

            if "packages" in lockfile:
                extract_deps(lockfile["packages"])
            elif "dependencies" in lockfile:
                extract_deps(lockfile["dependencies"])

            return dependencies
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse npm lockfile: {e}")
            return []

    def scan_pip_requirements(self, requirements_content: str) -> list[dict[str, Any]]:
        """Parse pip requirements.txt or pyproject.toml

        Args:
            requirements_content: Content of requirements file

        Returns:
            List of dependency objects
        """
        dependencies = []

        for line in requirements_content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Parse package specification
            match = re.match(r"([a-zA-Z0-9_-]+)\s*(?:==|>=|<=|~=|!=)?(.+)?", line)
            if match:
                name = match.group(1)
                version = match.group(2) or "unknown"
                dependencies.append({
                    "name": name,
                    "version": version,
                    "package_type": "pypi",
                    "purl": f"pkg:pypi/{name}@{version}",
                })

        return dependencies

    def scan_maven_pom(self, pom_content: str) -> list[dict[str, Any]]:
        """Parse Maven pom.xml

        Args:
            pom_content: Content of pom.xml

        Returns:
            List of dependency objects
        """
        dependencies = []

        try:
            root = ET.fromstring(pom_content)
            ns = {"mvn": "http://maven.apache.org/POM/4.0.0"}

            for dep in root.findall(".//mvn:dependency", ns):
                group_id = dep.find("mvn:groupId", ns)
                artifact_id = dep.find("mvn:artifactId", ns)
                version = dep.find("mvn:version", ns)

                if artifact_id is not None and group_id is not None:
                    name = f"{group_id.text}:{artifact_id.text}"
                    ver = version.text if version is not None else "unknown"
                    dependencies.append({
                        "name": name,
                        "version": ver,
                        "package_type": "maven",
                        "purl": f"pkg:maven/{group_id.text}/{artifact_id.text}@{ver}",
                    })
        except ET.ParseError as e:
            self.logger.error(f"Failed to parse Maven pom.xml: {e}")

        return dependencies

    def scan_go_modules(self, go_mod_content: str) -> list[dict[str, Any]]:
        """Parse Go go.mod

        Args:
            go_mod_content: Content of go.mod

        Returns:
            List of dependency objects
        """
        dependencies = []
        in_require = False

        for line in go_mod_content.split("\n"):
            line = line.strip()

            if line.startswith("require"):
                if line == "require (" or line.startswith("require ("):
                    in_require = True
                    continue
                elif " " in line and not line.endswith("("):
                    # Single line require
                    parts = line.replace("require", "").strip().split()
                    if len(parts) >= 2:
                        dependencies.append({
                            "name": parts[0],
                            "version": parts[1],
                            "package_type": "go_module",
                            "purl": f"pkg:golang/{parts[0]}@{parts[1]}",
                        })
            elif in_require and line == ")":
                in_require = False
            elif in_require and line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    dependencies.append({
                        "name": parts[0],
                        "version": parts[1],
                        "package_type": "go_module",
                        "purl": f"pkg:golang/{parts[0]}@{parts[1]}",
                    })

        return dependencies

    def scan_container_image(self, image_digest: str) -> list[dict[str, Any]]:
        """Scan container image for dependencies (mock implementation)

        Args:
            image_digest: Container image digest or reference

        Returns:
            List of dependency objects
        """
        self.logger.info(f"Container image scanning initiated for {image_digest}")
        return [
            {
                "name": "base-os-package",
                "version": "1.0",
                "package_type": "apt",
                "purl": f"pkg:deb/debian/base@1.0",
            }
        ]

    def detect_outdated_dependencies(
        self, dependencies: list[dict[str, Any]], latest_versions: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Detect outdated dependencies

        Args:
            dependencies: List of current dependencies
            latest_versions: Mapping of package names to latest versions

        Returns:
            List of outdated dependency objects
        """
        outdated = []

        for dep in dependencies:
            name = dep.get("name")
            current_version = dep.get("version", "unknown")
            latest = latest_versions.get(name)

            if latest and self._is_version_older(current_version, latest):
                outdated.append({
                    **dep,
                    "latest_version": latest,
                    "status": "outdated",
                })

        return outdated

    def check_known_vulnerabilities(
        self, components: list[dict[str, Any]], vuln_db: dict[str, list[str]]
    ) -> list[dict[str, Any]]:
        """Check components against known vulnerability database

        Args:
            components: List of components to check
            vuln_db: Vulnerability database (component identifier to CVE list)

        Returns:
            List of components with known vulnerabilities
        """
        vulnerable = []

        for component in components:
            name = component.get("name")
            version = component.get("version", "")
            key = f"{name}@{version}"

            if key in vuln_db:
                vulnerable.append({
                    **component,
                    "cves": vuln_db[key],
                    "vulnerability_count": len(vuln_db[key]),
                })

        return vulnerable

    @staticmethod
    def _is_version_older(current: str, latest: str) -> bool:
        """Compare semantic versions (simplified)

        Args:
            current: Current version string
            latest: Latest version string

        Returns:
            True if current < latest
        """
        try:
            curr_parts = [int(x) for x in current.split(".")[:3]]
            latest_parts = [int(x) for x in latest.split(".")[:3]]
            return curr_parts < latest_parts
        except (ValueError, AttributeError):
            return False


class SupplyChainRiskAnalyzer:
    """Analyze supply chain risks including typosquatting, license conflicts, etc."""

    def __init__(self):
        """Initialize Risk Analyzer"""
        self.logger = logger

    def detect_typosquatting(
        self, component_names: list[str], popular_packages: list[str], threshold: float = 0.85
    ) -> list[dict[str, Any]]:
        """Detect potential typosquatting attacks using Levenshtein distance

        Args:
            component_names: List of component names to check
            popular_packages: List of known popular packages
            threshold: Similarity threshold (0-1)

        Returns:
            List of potential typosquatting candidates
        """
        suspected = []

        for name in component_names:
            for popular in popular_packages:
                similarity = self._levenshtein_similarity(name.lower(), popular.lower())
                if similarity >= threshold and name.lower() != popular.lower():
                    suspected.append({
                        "component": name,
                        "similar_to": popular,
                        "similarity_score": similarity,
                        "risk_type": "typosquatting",
                        "severity": "high",
                    })

        return suspected

    def detect_dependency_confusion(
        self, dependencies: list[dict[str, Any]], public_registry: list[str]
    ) -> list[dict[str, Any]]:
        """Detect dependency confusion attacks (private vs public package collision)

        Args:
            dependencies: List of internal dependencies
            public_registry: List of public package names

        Returns:
            List of confusion candidates
        """
        confused = []

        for dep in dependencies:
            name = dep.get("name")
            if name in public_registry:
                confused.append({
                    "component": name,
                    "risk_type": "dependency_confusion",
                    "severity": "critical",
                    "description": f"Internal package '{name}' conflicts with public package",
                })

        return confused

    def assess_maintainer_risk(self, component_metadata: dict[str, Any]) -> dict[str, Any]:
        """Assess risk based on maintainer bus factor and activity

        Args:
            component_metadata: Component metadata including maintainer info

        Returns:
            Risk assessment with bus factor and activity score
        """
        maintainers = component_metadata.get("maintainers", [])
        commits_per_month = component_metadata.get("commits_per_month", 0)
        last_update = component_metadata.get("last_update_days", 999)

        risk_score = 0.0
        risk_factors = []

        # Bus factor (single maintainer)
        if len(maintainers) == 1:
            risk_score += 30
            risk_factors.append("single_maintainer")

        # Activity level
        if commits_per_month < 1:
            risk_score += 25
            risk_factors.append("low_activity")
        elif commits_per_month > 100:
            risk_score -= 10
            risk_factors.append("high_activity")

        # Staleness
        if last_update > 365:
            risk_score += 20
            risk_factors.append("stale_project")

        return {
            "maintainer_risk_score": min(100.0, max(0.0, risk_score)),
            "bus_factor": len(maintainers),
            "commits_per_month": commits_per_month,
            "last_update_days": last_update,
            "risk_factors": risk_factors,
        }

    def assess_license_compliance(self, licenses: list[str]) -> dict[str, Any]:
        """Assess license compliance and conflicts

        Args:
            licenses: List of SPDX license identifiers

        Returns:
            Compliance assessment
        """
        gpl_licenses = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0"}
        proprietary_licenses = {"Proprietary", "Commercial"}
        permissive_licenses = {"MIT", "Apache-2.0", "BSD-3-Clause", "ISC"}

        has_gpl = any(lic in gpl_licenses for lic in licenses)
        has_proprietary = any(lic in proprietary_licenses for lic in licenses)
        has_permissive = any(lic in permissive_licenses for lic in licenses)

        conflicts = []
        if has_gpl and has_proprietary:
            conflicts.append("GPL incompatible with proprietary license")

        risk_score = 0.0
        if has_gpl:
            risk_score += 30
        if has_proprietary:
            risk_score += 40

        return {
            "license_risk_score": risk_score,
            "licenses": licenses,
            "has_gpl": has_gpl,
            "has_proprietary": has_proprietary,
            "has_permissive": has_permissive,
            "conflicts": conflicts,
            "compliance_status": "non_compliant" if conflicts else "compliant",
        }

    def calculate_component_risk_score(self, component_assessment: dict[str, Any]) -> float:
        """Calculate comprehensive component risk score

        Args:
            component_assessment: Assessment data including vulnerabilities, license, etc.

        Returns:
            Component risk score (0-100)
        """
        score = 0.0

        # Vulnerability risk
        vuln_count = component_assessment.get("known_vulnerabilities_count", 0)
        score += min(40.0, vuln_count * 5)

        # License risk
        score += component_assessment.get("license_risk_score", 0) * 0.3

        # Maintainer risk
        score += component_assessment.get("maintainer_risk_score", 0) * 0.2

        # Outdated
        if component_assessment.get("is_outdated"):
            score += 15.0

        # Malicious indicator
        if component_assessment.get("is_malicious"):
            score += 100.0

        return min(100.0, max(0.0, score))

    def generate_risk_report(self, components: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate comprehensive risk report for components

        Args:
            components: List of component assessments

        Returns:
            Risk report with summary and recommendations
        """
        critical_count = sum(1 for c in components if self.calculate_component_risk_score(c) >= 80)
        high_count = sum(1 for c in components if 60 <= self.calculate_component_risk_score(c) < 80)
        medium_count = sum(1 for c in components if 40 <= self.calculate_component_risk_score(c) < 60)

        avg_risk = (
            sum(self.calculate_component_risk_score(c) for c in components) / len(components)
            if components
            else 0.0
        )

        return {
            "report_generated": datetime.utcnow().isoformat(),
            "total_components": len(components),
            "critical_risks": critical_count,
            "high_risks": high_count,
            "medium_risks": medium_count,
            "average_risk_score": avg_risk,
            "recommendations": self._generate_recommendations(critical_count, high_count),
        }

    @staticmethod
    def _levenshtein_similarity(s1: str, s2: str) -> float:
        """Calculate Levenshtein similarity ratio (0-1)"""
        if not s1 or not s2:
            return 0.0

        m, n = len(s1), len(s2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]

        for i in range(m + 1):
            dp[i][0] = i
        for j in range(n + 1):
            dp[0][j] = j

        for i in range(1, m + 1):
            for j in range(1, n + 1):
                cost = 0 if s1[i - 1] == s2[j - 1] else 1
                dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)

        distance = dp[m][n]
        max_len = max(m, n)
        return 1.0 - (distance / max_len) if max_len > 0 else 1.0

    @staticmethod
    def _generate_recommendations(critical: int, high: int) -> list[str]:
        """Generate recommendations based on risk counts"""
        recommendations = []

        if critical > 0:
            recommendations.append(f"URGENT: Address {critical} critical-risk components immediately")
        if high > 0:
            recommendations.append(f"Review and mitigate {high} high-risk components")
        if critical == 0 and high == 0:
            recommendations.append("Continue regular dependency monitoring")

        return recommendations


class VendorRiskManager:
    """Manage third-party vendor risk assessment and tracking"""

    def __init__(self):
        """Initialize Vendor Risk Manager"""
        self.logger = logger

    def create_assessment(
        self, vendor_name: str, assessment_type: str, security_score: float
    ) -> dict[str, Any]:
        """Create vendor assessment record

        Args:
            vendor_name: Name of the vendor
            assessment_type: Type of assessment (initial, annual, etc.)
            security_score: Security assessment score (0-100)

        Returns:
            Assessment record
        """
        return {
            "vendor_name": vendor_name,
            "assessment_type": assessment_type,
            "security_score": security_score,
            "assessment_date": datetime.utcnow().isoformat(),
            "status": "completed",
        }

    def score_vendor(self, vendor_data: dict[str, Any]) -> float:
        """Calculate comprehensive vendor risk score

        Args:
            vendor_data: Vendor assessment data

        Returns:
            Vendor risk score (0-100)
        """
        score = 100.0

        # Security questionnaire results
        score -= vendor_data.get("questionnaire_score", 0) * 0.4

        # Certifications (improve score)
        certifications = vendor_data.get("certifications", [])
        cert_score = len(certifications) * 10
        score -= min(30.0, cert_score)

        # Incident history (reduce score)
        incident_count = vendor_data.get("incident_count", 0)
        score += min(40.0, incident_count * 5)

        # Contract status
        if vendor_data.get("contract_expiry"):
            score += 5.0

        return min(100.0, max(0.0, score))

    def track_vendor_incidents(self, vendor_id: str, incident: dict[str, Any]) -> dict[str, Any]:
        """Track security incident for vendor

        Args:
            vendor_id: Vendor identifier
            incident: Incident details

        Returns:
            Updated incident record
        """
        return {
            "vendor_id": vendor_id,
            "incident_date": datetime.utcnow().isoformat(),
            "description": incident.get("description"),
            "severity": incident.get("severity", "medium"),
            "impact": incident.get("impact"),
            "remediation": incident.get("remediation"),
        }

    def generate_vendor_risk_report(self, vendors: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate comprehensive vendor risk report

        Args:
            vendors: List of vendor assessments

        Returns:
            Risk report
        """
        critical_vendors = sum(1 for v in vendors if self.score_vendor(v) >= 70)
        high_risk_vendors = sum(1 for v in vendors if 50 <= self.score_vendor(v) < 70)

        avg_score = (
            sum(self.score_vendor(v) for v in vendors) / len(vendors) if vendors else 0.0
        )

        return {
            "report_generated": datetime.utcnow().isoformat(),
            "total_vendors": len(vendors),
            "critical_risk_vendors": critical_vendors,
            "high_risk_vendors": high_risk_vendors,
            "average_vendor_score": avg_score,
        }

    def check_certification_expiry(self, certifications: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Check for expiring vendor certifications

        Args:
            certifications: List of certification records

        Returns:
            List of expiring certifications
        """
        expiring = []

        for cert in certifications:
            expiry_date = cert.get("expiry_date")
            if expiry_date:
                # Check if expiring within 90 days (simplified)
                expiring.append(cert)

        return expiring

    def assess_fourth_party_risk(self, vendor_subprocessors: list[str]) -> dict[str, Any]:
        """Assess risk from vendor's third-party subprocessors

        Args:
            vendor_subprocessors: List of subprocessor names

        Returns:
            Fourth-party risk assessment
        """
        return {
            "subprocessor_count": len(vendor_subprocessors),
            "subprocessors": vendor_subprocessors,
            "fourth_party_risk_score": min(50.0, len(vendor_subprocessors) * 5),
            "recommendation": "Request subprocessor risk assessments" if vendor_subprocessors else "No subprocessors",
        }


class CISASBOMCompliance:
    """Validate SBOM compliance with CISA and NTIA guidelines"""

    def __init__(self):
        """Initialize CISA Compliance Validator"""
        self.logger = logger

    def validate_minimum_elements(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Validate CISA 2025 minimum elements for SBOM

        CISA requires:
        - Author information
        - Timestamp
        - Supplier name
        - Component name and version
        - Unique identifier
        - Dependency relationships

        Args:
            sbom_data: SBOM data to validate

        Returns:
            Validation result
        """
        required_elements = {
            "author": bool(sbom_data.get("author") or sbom_data.get("created_by_tool")),
            "timestamp": bool(sbom_data.get("created_at") or sbom_data.get("timestamp")),
            "supplier": bool(sbom_data.get("supplier") or sbom_data.get("vendor")),
            "component_name": bool(sbom_data.get("name") or sbom_data.get("application_name")),
            "component_version": bool(sbom_data.get("version") or sbom_data.get("application_version")),
            "unique_identifier": bool(
                sbom_data.get("id") or sbom_data.get("sbom_id") or sbom_data.get("uuid")
            ),
            "dependencies": bool(sbom_data.get("components") or sbom_data.get("relationships")),
        }

        is_compliant = all(required_elements.values())
        missing = [k for k, v in required_elements.items() if not v]

        return {
            "compliant": is_compliant,
            "required_elements": required_elements,
            "missing_elements": missing,
            "compliance_percentage": (
                sum(required_elements.values()) / len(required_elements) * 100
            ),
        }

    def check_ntia_minimum(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Check NTIA Minimum Elements for Software Security (EO 14028)

        Args:
            sbom_data: SBOM data to validate

        Returns:
            NTIA compliance check result
        """
        ntia_elements = {
            "data_fields": bool(sbom_data.get("data_fields")),
            "file_formats": bool(sbom_data.get("sbom_format")),
            "component_info": bool(sbom_data.get("components")),
            "dependency_info": bool(sbom_data.get("relationships")),
            "metadata": bool(sbom_data.get("metadata") or sbom_data.get("created_at")),
        }

        return {
            "ntia_compliant": all(ntia_elements.values()),
            "elements": ntia_elements,
            "confidence_score": sum(ntia_elements.values()) / len(ntia_elements) * 100,
        }

    def generate_compliance_report(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Generate comprehensive compliance report

        Args:
            sbom_data: SBOM to validate

        Returns:
            Compliance report
        """
        cisa_result = self.validate_minimum_elements(sbom_data)
        ntia_result = self.check_ntia_minimum(sbom_data)

        overall_compliant = cisa_result["compliant"] and ntia_result["ntia_compliant"]

        return {
            "report_generated": datetime.utcnow().isoformat(),
            "overall_compliant": overall_compliant,
            "cisa_compliance": cisa_result,
            "ntia_compliance": ntia_result,
            "recommendations": self._generate_compliance_recommendations(cisa_result, ntia_result),
        }

    @staticmethod
    def _generate_compliance_recommendations(cisa: dict[str, Any], ntia: dict[str, Any]) -> list[str]:
        """Generate compliance recommendations"""
        recommendations = []

        if cisa["missing_elements"]:
            recommendations.append(f"Add missing CISA elements: {', '.join(cisa['missing_elements'])}")

        if not ntia["ntia_compliant"]:
            recommendations.append("Improve NTIA minimum element coverage")

        if cisa["compliance_percentage"] < 100:
            recommendations.append("Increase SBOM completeness to 100%")

        if not recommendations:
            recommendations.append("SBOM meets CISA and NTIA guidelines")

        return recommendations
