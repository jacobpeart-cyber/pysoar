"""Threat intelligence integration manager"""

import asyncio
from typing import Any, Optional

from src.core.logging import get_logger
from src.integrations.abuseipdb import AbuseIPDBProvider
from src.integrations.base import ThreatIntelProvider
from src.integrations.greynoise import GreyNoiseProvider
from src.integrations.shodan import ShodanProvider
from src.integrations.virustotal import VirusTotalProvider

logger = get_logger(__name__)


class ThreatIntelManager:
    """Manager for coordinating threat intelligence lookups across providers"""

    def __init__(self):
        self.providers: dict[str, ThreatIntelProvider] = {
            "virustotal": VirusTotalProvider(),
            "abuseipdb": AbuseIPDBProvider(),
            "shodan": ShodanProvider(),
            "greynoise": GreyNoiseProvider(),
        }

    def get_configured_providers(self) -> list[str]:
        """Get list of configured provider names"""
        return [
            name for name, provider in self.providers.items() if provider.is_configured
        ]

    async def enrich_ip(
        self,
        ip: str,
        providers: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Enrich an IP address using multiple providers"""
        results = {"ip": ip, "providers": {}}

        target_providers = providers or self.get_configured_providers()

        async def lookup_with_provider(provider_name: str) -> tuple[str, dict]:
            provider = self.providers.get(provider_name)
            if not provider or not provider.is_configured:
                return provider_name, {"error": "Provider not configured"}

            try:
                result = await provider.lookup_ip(ip)
                return provider_name, result
            except Exception as e:
                logger.error(f"IP lookup failed for {provider_name}", error=str(e))
                return provider_name, {"error": str(e)}

        # Run lookups concurrently
        tasks = [lookup_with_provider(p) for p in target_providers]
        provider_results = await asyncio.gather(*tasks)

        for provider_name, result in provider_results:
            results["providers"][provider_name] = result

        # Calculate aggregated score
        results["aggregated"] = self._aggregate_ip_results(results["providers"])

        return results

    async def enrich_domain(
        self,
        domain: str,
        providers: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Enrich a domain using multiple providers"""
        results = {"domain": domain, "providers": {}}

        # Only some providers support domain lookup
        domain_providers = ["virustotal", "shodan"]
        target_providers = [
            p for p in (providers or domain_providers)
            if p in domain_providers and self.providers.get(p, None) and self.providers[p].is_configured
        ]

        async def lookup_with_provider(provider_name: str) -> tuple[str, dict]:
            provider = self.providers.get(provider_name)
            if not provider:
                return provider_name, {"error": "Provider not found"}

            try:
                result = await provider.lookup_domain(domain)
                return provider_name, result
            except Exception as e:
                logger.error(f"Domain lookup failed for {provider_name}", error=str(e))
                return provider_name, {"error": str(e)}

        tasks = [lookup_with_provider(p) for p in target_providers]
        provider_results = await asyncio.gather(*tasks)

        for provider_name, result in provider_results:
            results["providers"][provider_name] = result

        return results

    async def enrich_hash(
        self,
        file_hash: str,
        providers: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Enrich a file hash using multiple providers"""
        results = {"hash": file_hash, "providers": {}}

        # Only VirusTotal supports hash lookup in our providers
        hash_providers = ["virustotal"]
        target_providers = [
            p for p in (providers or hash_providers)
            if p in hash_providers and self.providers.get(p, None) and self.providers[p].is_configured
        ]

        async def lookup_with_provider(provider_name: str) -> tuple[str, dict]:
            provider = self.providers.get(provider_name)
            if not provider:
                return provider_name, {"error": "Provider not found"}

            try:
                result = await provider.lookup_hash(file_hash)
                return provider_name, result
            except Exception as e:
                logger.error(f"Hash lookup failed for {provider_name}", error=str(e))
                return provider_name, {"error": str(e)}

        tasks = [lookup_with_provider(p) for p in target_providers]
        provider_results = await asyncio.gather(*tasks)

        for provider_name, result in provider_results:
            results["providers"][provider_name] = result

        return results

    async def enrich_url(
        self,
        url: str,
        providers: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Enrich a URL using providers that support it"""
        results = {"url": url, "providers": {}}

        # Only VirusTotal supports URL lookup in our providers
        url_providers = ["virustotal"]
        target_providers = [
            p for p in (providers or url_providers)
            if p in url_providers and self.providers.get(p, None) and self.providers[p].is_configured
        ]

        for provider_name in target_providers:
            provider = self.providers.get(provider_name)
            if not provider:
                continue

            try:
                result = await provider.lookup_url(url)
                results["providers"][provider_name] = result
            except Exception as e:
                logger.error(f"URL lookup failed for {provider_name}", error=str(e))
                results["providers"][provider_name] = {"error": str(e)}

        return results

    def _aggregate_ip_results(self, provider_results: dict) -> dict[str, Any]:
        """Aggregate results from multiple providers into a single score"""
        scores = []
        tags = set()
        is_malicious = False

        for provider_name, result in provider_results.items():
            if "error" in result:
                continue

            if provider_name == "virustotal":
                malicious = result.get("malicious", 0)
                total = malicious + result.get("harmless", 0) + result.get("suspicious", 0)
                if total > 0:
                    scores.append(malicious / total * 100)
                if malicious > 3:
                    is_malicious = True
                tags.update(result.get("tags", []))

            elif provider_name == "abuseipdb":
                score = result.get("abuse_confidence_score", 0)
                scores.append(score)
                if score > 50:
                    is_malicious = True

            elif provider_name == "greynoise":
                if result.get("classification") == "malicious":
                    is_malicious = True
                    scores.append(80)
                elif result.get("noise"):
                    scores.append(30)
                tags.update(result.get("tags", []))

        avg_score = sum(scores) / len(scores) if scores else 0

        return {
            "threat_score": round(avg_score, 2),
            "is_malicious": is_malicious,
            "tags": list(tags),
            "providers_queried": len(provider_results),
            "providers_with_data": len([r for r in provider_results.values() if "error" not in r]),
        }

    async def close(self) -> None:
        """Close all provider connections"""
        for provider in self.providers.values():
            await provider.close()


# Global instance
threat_intel_manager = ThreatIntelManager()
