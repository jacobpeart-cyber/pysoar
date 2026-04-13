"""Risk Quantification Engine

Implements FAIR (Factor Analysis of Information Risk) Monte Carlo simulation
and advanced risk analytics.
"""

import json
from dataclasses import dataclass
from typing import Any, Optional

import numpy as np
from scipy.stats import beta

from src.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class FAIRAnalysisResult:
    """Results from FAIR Monte Carlo simulation"""

    ale_mean: float
    ale_p10: float
    ale_p50: float
    ale_p90: float
    ale_p99: float
    loss_exceedance_curve: dict
    tef_distribution: list
    vuln_distribution: list
    lef_distribution: list
    lm_distribution: list
    ale_distribution: list


class FAIREngine:
    """FAIR Model Monte Carlo simulation engine"""

    def __init__(self):
        """Initialize FAIR engine"""
        self.logger = logger

    def sample_pert_distribution(
        self, min_val: float, mode_val: float, max_val: float, size: int = 1
    ) -> np.ndarray:
        """
        Sample from PERT (Program Evaluation Review Technique) / Beta distribution.

        The PERT distribution is ideal for risk modeling as it uses expert estimates:
        - min: pessimistic (low probability) estimate
        - mode: most likely estimate
        - max: optimistic estimate

        Args:
            min_val: Minimum value
            mode_val: Most likely (mode) value
            max_val: Maximum value
            size: Number of samples

        Returns:
            Samples from PERT distribution
        """
        if min_val == mode_val == max_val:
            return np.full(size, min_val)

        # Convert PERT to Beta distribution parameters
        # PERT uses: mu = (a + 4*m + b) / 6
        # Then transforms Beta(a, b) to fit [min, max]
        range_val = max_val - min_val

        if range_val <= 0:
            return np.full(size, min_val)

        # Normalized mode in [0, 1]
        mode_normalized = (mode_val - min_val) / range_val

        # Beta distribution shape parameters
        # Using standard PERT formulation
        mu = (min_val + 4 * mode_val + max_val) / 6
        variance = ((max_val - min_val) ** 2) / 36

        if variance <= 0:
            return np.full(size, mu)

        # Convert to Beta parameters
        p = ((mu - min_val) / range_val) if range_val > 0 else 0.5
        q = ((max_val - mu) / range_val) if range_val > 0 else 0.5

        if p <= 0 or q <= 0:
            return np.full(size, mu)

        # Sample from Beta and scale to [min_val, max_val]
        try:
            samples = beta.rvs(a=p, b=q, size=size)
            return min_val + samples * range_val
        except Exception as e:
            self.logger.warning(f"Beta sampling failed, using uniform: {e}")
            return np.random.uniform(min_val, max_val, size=size)

    def calculate_tef(self, tef_params: dict, iterations: int = 10000) -> np.ndarray:
        """
        Calculate Threat Event Frequency (TEF) distribution.

        TEF represents the number of threat events per year.

        Args:
            tef_params: Dictionary with 'min', 'mode', 'max' keys
            iterations: Number of iterations for simulation

        Returns:
            Array of TEF samples
        """
        tef = self.sample_pert_distribution(
            tef_params["min"], tef_params["mode"], tef_params["max"], size=iterations
        )
        # Ensure non-negative
        tef = np.maximum(tef, 0)
        return tef

    def calculate_vulnerability(
        self,
        tcap_samples: np.ndarray,
        rs_samples: np.ndarray,
    ) -> np.ndarray:
        """
        Calculate Vulnerability from Threat Capability and Resistance Strength.

        Vulnerability = Threat Capability × (1 - Resistance Strength)
        This represents the probability that a threat will successfully exploit vulnerability.

        Args:
            tcap_samples: Threat Capability samples (0-1)
            rs_samples: Resistance Strength samples (0-1)

        Returns:
            Vulnerability samples (0-1)
        """
        # Clamp to valid ranges
        tcap = np.clip(tcap_samples, 0, 1)
        rs = np.clip(rs_samples, 0, 1)

        # Vulnerability calculation
        vuln = tcap * (1 - rs)
        return np.clip(vuln, 0, 1)

    def calculate_lef(
        self,
        tef_samples: np.ndarray,
        vuln_samples: np.ndarray,
    ) -> np.ndarray:
        """
        Calculate Loss Event Frequency (LEF).

        LEF = TEF × Vulnerability
        Represents the number of successful loss events per year.

        Args:
            tef_samples: Threat Event Frequency samples
            vuln_samples: Vulnerability samples

        Returns:
            Loss Event Frequency samples
        """
        lef = tef_samples * vuln_samples
        return np.maximum(lef, 0)

    def calculate_loss_magnitude(
        self,
        primary_samples: np.ndarray,
        secondary_samples: np.ndarray,
        secondary_lef_samples: np.ndarray,
    ) -> np.ndarray:
        """
        Calculate total loss per event.

        LM = Primary Loss + (Secondary Loss × Secondary LEF)

        Args:
            primary_samples: Primary loss per event samples
            secondary_samples: Secondary loss per event samples
            secondary_lef_samples: Secondary loss event frequency

        Returns:
            Loss magnitude samples
        """
        lm = primary_samples + (secondary_samples * secondary_lef_samples)
        return np.maximum(lm, 0)

    def calculate_ale(
        self,
        lef_samples: np.ndarray,
        lm_samples: np.ndarray,
    ) -> np.ndarray:
        """
        Calculate Annualized Loss Expectancy (ALE).

        ALE = LEF × LM (across all simulations)

        Args:
            lef_samples: Loss Event Frequency samples
            lm_samples: Loss Magnitude samples

        Returns:
            Annualized Loss Expectancy samples
        """
        ale = lef_samples * lm_samples
        return np.maximum(ale, 0)

    def generate_loss_exceedance_curve(
        self, ale_samples: np.ndarray, num_points: int = 100
    ) -> dict:
        """
        Generate loss exceedance curve: P(Loss > X).

        The exceedance curve shows the probability that losses will exceed given thresholds.

        Args:
            ale_samples: Annualized Loss Expectancy samples
            num_points: Number of points for the curve

        Returns:
            Dictionary with x_values (loss thresholds) and y_values (probabilities)
        """
        if len(ale_samples) == 0:
            return {"x_values": [], "y_values": []}

        # Generate threshold values from 0 to max observed loss
        max_loss = np.max(ale_samples)
        if max_loss <= 0:
            return {"x_values": [0], "y_values": [1.0]}

        thresholds = np.linspace(0, max_loss, num_points)
        exceedance_probs = []

        for threshold in thresholds:
            # Probability of exceeding threshold
            prob = np.mean(ale_samples > threshold)
            exceedance_probs.append(float(prob))

        return {
            "x_values": [float(x) for x in thresholds],
            "y_values": exceedance_probs,
        }

    def run_simulation(self, analysis_data: dict, iterations: int = 10000) -> FAIRAnalysisResult:
        """
        Run complete FAIR Monte Carlo simulation.

        Args:
            analysis_data: Dictionary containing FAIR analysis parameters
            iterations: Number of iterations for Monte Carlo

        Returns:
            FAIRAnalysisResult with calculated metrics
        """
        try:
            # Sample TEF distribution
            tef_samples = self.sample_pert_distribution(
                analysis_data["tef_min"],
                analysis_data["tef_mode"],
                analysis_data["tef_max"],
                size=iterations,
            )
            tef_samples = np.maximum(tef_samples, 0)

            # Sample Threat Capability
            tcap_samples = self.sample_pert_distribution(
                analysis_data["tcap_min"],
                analysis_data["tcap_mode"],
                analysis_data["tcap_max"],
                size=iterations,
            )

            # Sample Resistance Strength
            rs_samples = self.sample_pert_distribution(
                analysis_data["rs_min"],
                analysis_data["rs_mode"],
                analysis_data["rs_max"],
                size=iterations,
            )

            # Calculate Vulnerability
            vuln_samples = self.calculate_vulnerability(tcap_samples, rs_samples)

            # Calculate LEF
            lef_samples = self.calculate_lef(tef_samples, vuln_samples)

            # Sample primary loss magnitude
            primary_loss_samples = self.sample_pert_distribution(
                analysis_data["primary_loss_min"],
                analysis_data["primary_loss_mode"],
                analysis_data["primary_loss_max"],
                size=iterations,
            )
            primary_loss_samples = np.maximum(primary_loss_samples, 0)

            # Sample secondary loss magnitude
            secondary_loss_samples = self.sample_pert_distribution(
                analysis_data["secondary_loss_min"],
                analysis_data["secondary_loss_mode"],
                analysis_data["secondary_loss_max"],
                size=iterations,
            )
            secondary_loss_samples = np.maximum(secondary_loss_samples, 0)

            # Secondary loss event frequency
            secondary_lef = analysis_data.get("secondary_loss_event_frequency", 1.0)

            # Calculate total loss magnitude
            lm_samples = self.calculate_loss_magnitude(
                primary_loss_samples,
                secondary_loss_samples,
                np.full(iterations, secondary_lef),
            )

            # Calculate ALE
            ale_samples = self.calculate_ale(lef_samples, lm_samples)

            # Calculate percentiles
            ale_mean = float(np.mean(ale_samples))
            ale_p10 = float(np.percentile(ale_samples, 10))
            ale_p50 = float(np.percentile(ale_samples, 50))
            ale_p90 = float(np.percentile(ale_samples, 90))
            ale_p99 = float(np.percentile(ale_samples, 99))

            # Generate loss exceedance curve
            loss_exceedance_curve = self.generate_loss_exceedance_curve(ale_samples)

            self.logger.info(
                f"FAIR simulation completed",
                extra={
                    "iterations": iterations,
                    "ale_mean": ale_mean,
                    "ale_p50": ale_p50,
                },
            )

            return FAIRAnalysisResult(
                ale_mean=ale_mean,
                ale_p10=ale_p10,
                ale_p50=ale_p50,
                ale_p90=ale_p90,
                ale_p99=ale_p99,
                loss_exceedance_curve=loss_exceedance_curve,
                tef_distribution=tef_samples.tolist(),
                vuln_distribution=vuln_samples.tolist(),
                lef_distribution=lef_samples.tolist(),
                lm_distribution=lm_samples.tolist(),
                ale_distribution=ale_samples.tolist(),
            )

        except Exception as e:
            self.logger.error(f"FAIR simulation failed: {e}")
            raise

    def generate_risk_report(self, analysis_result: FAIRAnalysisResult) -> dict:
        """
        Generate comprehensive risk report from simulation results.

        Args:
            analysis_result: FAIRAnalysisResult from run_simulation

        Returns:
            Dictionary with risk report data
        """
        ale_dist = np.array(analysis_result.ale_distribution)

        report = {
            "ale_statistics": {
                "mean": analysis_result.ale_mean,
                "median": analysis_result.ale_p50,
                "p10": analysis_result.ale_p10,
                "p90": analysis_result.ale_p90,
                "p99": analysis_result.ale_p99,
                "std_dev": float(np.std(ale_dist)),
                "min": float(np.min(ale_dist)),
                "max": float(np.max(ale_dist)),
            },
            "loss_exceedance_curve": analysis_result.loss_exceedance_curve,
            "risk_distribution": {
                "low_risk_count": int(np.sum(ale_dist < np.percentile(ale_dist, 33))),
                "medium_risk_count": int(
                    np.sum(
                        (ale_dist >= np.percentile(ale_dist, 33))
                        & (ale_dist < np.percentile(ale_dist, 67))
                    )
                ),
                "high_risk_count": int(np.sum(ale_dist >= np.percentile(ale_dist, 67))),
            },
        }

        return report


class RiskAggregator:
    """Aggregates and analyzes risks across the organization"""

    def __init__(self):
        """Initialize risk aggregator"""
        self.logger = logger

    def aggregate_organizational_risk(self, risks: list[dict]) -> dict:
        """
        Aggregate risks across organization.

        Args:
            risks: List of risk dictionaries with ALE values

        Returns:
            Aggregated risk metrics
        """
        if not risks:
            return {
                "total_ale": 0,
                "count": 0,
                "average_ale": 0,
                "risks_by_category": {},
            }

        ales = [r.get("ale_mean", 0) for r in risks]
        total_ale = sum(ales)

        # Aggregate by category
        risks_by_category = {}
        for risk in risks:
            cat = risk.get("category", "unknown")
            if cat not in risks_by_category:
                risks_by_category[cat] = []
            risks_by_category[cat].append(risk.get("ale_mean", 0))

        category_totals = {
            cat: sum(ales) for cat, ales in risks_by_category.items()
        }

        return {
            "total_ale": total_ale,
            "count": len(risks),
            "average_ale": total_ale / len(risks) if risks else 0,
            "risks_by_category": category_totals,
        }

    def generate_risk_heatmap(self, risks: list[dict]) -> dict:
        """
        Generate risk heatmap (impact vs likelihood matrix).

        Args:
            risks: List of risk dictionaries

        Returns:
            Heatmap data for visualization
        """
        # 5x5 matrix: likelihood (rows) x impact (columns)
        heatmap = [[0 for _ in range(5)] for _ in range(5)]

        for risk in risks:
            likelihood = min(4, int(risk.get("likelihood", 1) * 5))
            impact = min(4, int(risk.get("impact", 1) * 5))
            heatmap[likelihood][impact] += 1

        return {
            "matrix": heatmap,
            "likelihood_labels": ["Very Low", "Low", "Medium", "High", "Very High"],
            "impact_labels": ["Very Low", "Low", "Medium", "High", "Very High"],
        }

    def calculate_portfolio_var(
        self, ale_samples: list[list[float]], confidence: float = 0.95
    ) -> float:
        """
        Calculate Value at Risk (VaR) for portfolio of risks.

        VaR at 95% confidence = 95th percentile of losses.

        Args:
            ale_samples: List of ALE distribution samples for each risk
            confidence: Confidence level (default 95%)

        Returns:
            VaR value
        """
        if not ale_samples:
            return 0.0

        # Sum across risks for each iteration
        portfolio_losses = np.sum(
            np.array(ale_samples), axis=0
        ) if ale_samples else np.array([])

        if len(portfolio_losses) == 0:
            return 0.0

        percentile = confidence * 100
        var = float(np.percentile(portfolio_losses, percentile))
        return var

    def rank_risks_by_ale(self, risks: list[dict]) -> list[dict]:
        """
        Rank risks by Annualized Loss Expectancy.

        Args:
            risks: List of risk dictionaries

        Returns:
            Sorted list of risks by ALE (descending)
        """
        sorted_risks = sorted(
            risks, key=lambda x: x.get("ale_mean", 0), reverse=True
        )
        return sorted_risks

    def compare_treatment_options(
        self, risk_ale: float, treatment_options: list[dict]
    ) -> dict:
        """
        Compare cost-benefit of different treatment options.

        Args:
            risk_ale: Current ALE of the risk
            treatment_options: List of treatments with cost and effectiveness

        Returns:
            Comparison with ROI calculations
        """
        analysis = []

        for option in treatment_options:
            cost = option.get("cost", 0)
            effectiveness = option.get("effectiveness", 0)  # 0-1

            # Residual risk after treatment
            residual_ale = risk_ale * (1 - effectiveness)

            # Annual savings
            annual_savings = risk_ale - residual_ale

            # ROI (assume control life of 5 years)
            total_cost_5yr = cost * 5
            total_savings_5yr = annual_savings * 5
            roi = (
                ((total_savings_5yr - total_cost_5yr) / total_cost_5yr) * 100
                if total_cost_5yr > 0
                else 0
            )

            analysis.append(
                {
                    "option": option.get("name", "unknown"),
                    "annual_cost": cost,
                    "effectiveness": effectiveness,
                    "residual_ale": residual_ale,
                    "annual_savings": annual_savings,
                    "roi_5yr_percent": roi,
                }
            )

        # Sort by ROI
        analysis.sort(key=lambda x: x["roi_5yr_percent"], reverse=True)
        return {"treatments": analysis}


class ControlEffectivenessAnalyzer:
    """Analyzes control effectiveness and ROI"""

    def __init__(self):
        """Initialize control analyzer"""
        self.logger = logger

    def assess_control_roi(
        self, unmitigated_ale: float, mitigated_ale: float, annual_control_cost: float
    ) -> dict:
        """
        Assess ROI of a control.

        Args:
            unmitigated_ale: ALE without control
            mitigated_ale: ALE with control in place
            annual_control_cost: Annual cost to operate control

        Returns:
            ROI analysis
        """
        annual_benefit = unmitigated_ale - mitigated_ale
        net_annual_benefit = annual_benefit - annual_control_cost

        # 5-year horizon
        total_benefit_5yr = annual_benefit * 5
        total_cost_5yr = annual_control_cost * 5
        roi_5yr = (
            ((total_benefit_5yr - total_cost_5yr) / total_cost_5yr) * 100
            if total_cost_5yr > 0
            else 0
        )

        payback_months = (
            (annual_control_cost / annual_benefit) * 12
            if annual_benefit > 0
            else float("inf")
        )

        return {
            "annual_benefit": annual_benefit,
            "annual_cost": annual_control_cost,
            "net_annual_benefit": net_annual_benefit,
            "roi_5yr_percent": roi_5yr,
            "payback_period_months": payback_months,
            "effective": net_annual_benefit > 0,
        }

    def recommend_controls(
        self, controls: list[dict], budget_constraint: Optional[float] = None
    ) -> list[dict]:
        """
        Recommend controls based on ROI.

        Args:
            controls: List of control dictionaries with ROI data
            budget_constraint: Maximum annual budget

        Returns:
            Ranked list of recommended controls
        """
        # Filter by effectiveness
        effective_controls = [c for c in controls if c.get("net_annual_benefit", 0) > 0]

        # Sort by ROI
        recommended = sorted(
            effective_controls, key=lambda x: x.get("roi_5yr_percent", 0), reverse=True
        )

        # Apply budget constraint if provided
        if budget_constraint:
            selected = []
            cumulative_cost = 0
            for control in recommended:
                cost = control.get("annual_cost", 0)
                if cumulative_cost + cost <= budget_constraint:
                    selected.append(control)
                    cumulative_cost += cost

            recommended = selected

        return recommended

    def simulate_control_implementation(
        self, baseline_ale: float, controls: list[dict]
    ) -> dict:
        """
        What-if analysis: compute the impact of implementing multiple controls.

        Args:
            baseline_ale: Baseline ALE without any controls
            controls: List of controls to implement

        Returns:
            Simulation results
        """
        cumulative_effectiveness = 0
        cumulative_cost = 0

        implementation_steps = []

        for i, control in enumerate(controls, 1):
            effectiveness = control.get("effectiveness", 0)
            cost = control.get("annual_cost", 0)

            # Stacking effectiveness (assumes some redundancy)
            cumulative_effectiveness += effectiveness * (1 - cumulative_effectiveness)
            cumulative_cost += cost

            residual_ale = baseline_ale * (1 - cumulative_effectiveness)

            implementation_steps.append(
                {
                    "step": i,
                    "control": control.get("name", f"Control {i}"),
                    "cumulative_effectiveness": cumulative_effectiveness,
                    "residual_ale": residual_ale,
                    "cumulative_cost": cumulative_cost,
                }
            )

        return {
            "baseline_ale": baseline_ale,
            "final_residual_ale": implementation_steps[-1]["residual_ale"]
            if implementation_steps
            else baseline_ale,
            "total_effectiveness": cumulative_effectiveness,
            "total_annual_cost": cumulative_cost,
            "annual_risk_reduction": baseline_ale
            * cumulative_effectiveness
            - cumulative_cost,
            "implementation_steps": implementation_steps,
        }

    def gap_analysis(
        self, all_risks: list[dict], protected_risks: list[dict]
    ) -> dict:
        """
        Identify gaps in control coverage.

        Args:
            all_risks: All identified risks
            protected_risks: Risks with adequate controls

        Returns:
            Gap analysis report
        """
        all_risk_ids = set(r.get("id") for r in all_risks)
        protected_risk_ids = set(r.get("id") for r in protected_risks)

        unprotected_ids = all_risk_ids - protected_risk_ids
        unprotected_risks = [r for r in all_risks if r.get("id") in unprotected_ids]

        total_unprotected_ale = sum(r.get("ale_mean", 0) for r in unprotected_risks)

        return {
            "unprotected_risks_count": len(unprotected_risks),
            "total_unprotected_ale": total_unprotected_ale,
            "coverage_percent": (
                (len(protected_risks) / len(all_risks) * 100) if all_risks else 0
            ),
            "unprotected_risks": unprotected_risks,
        }


class BIAEngine:
    """Business Impact Assessment analysis engine"""

    def __init__(self):
        """Initialize BIA engine"""
        self.logger = logger

    def assess_business_impact(self, bia_data: dict) -> dict:
        """
        Assess business impact of asset disruption.

        Args:
            bia_data: Dictionary with BIA parameters

        Returns:
            Impact assessment results
        """
        financial_impact = bia_data.get("financial_impact_per_hour_usd", 0)
        rto_hours = bia_data.get("rto_hours", 0)
        reputational_score = bia_data.get("reputational_impact_score", 0)
        regulatory_score = bia_data.get("regulatory_impact_score", 0)

        # Calculate downtime cost
        maximum_downtime_cost = financial_impact * rto_hours

        # Composite impact score (0-100)
        composite_score = (
            (maximum_downtime_cost / 100000) * 0.4
            + reputational_score * 0.3
            + regulatory_score * 0.3
        )
        composite_score = min(100, composite_score)

        return {
            "maximum_downtime_cost_usd": maximum_downtime_cost,
            "rto_hours": rto_hours,
            "reputational_impact": reputational_score,
            "regulatory_impact": regulatory_score,
            "composite_impact_score": composite_score,
        }

    def calculate_downtime_cost(
        self, hourly_rate: float, downtime_hours: float
    ) -> float:
        """
        Calculate cost of downtime.

        Args:
            hourly_rate: Cost per hour
            downtime_hours: Duration of downtime

        Returns:
            Total downtime cost
        """
        return hourly_rate * downtime_hours

    def identify_critical_dependencies(self, asset: dict) -> list[dict]:
        """
        Identify critical dependencies for an asset.

        Args:
            asset: Asset BIA data

        Returns:
            List of critical dependencies
        """
        dependencies = asset.get("dependencies", "[]")

        try:
            if isinstance(dependencies, str):
                deps = json.loads(dependencies)
            else:
                deps = dependencies

            # Filter to critical dependencies
            critical = [d for d in deps if d.get("criticality", "low") == "critical"]
            return critical

        except Exception as e:
            self.logger.error(f"Error parsing dependencies: {e}")
            return []

    def generate_continuity_requirements(self, bia_data: dict) -> dict:
        """
        Generate business continuity requirements from BIA.

        Args:
            bia_data: BIA assessment data

        Returns:
            Continuity requirements
        """
        return {
            "rto_hours": bia_data.get("rto_hours", 0),
            "rpo_hours": bia_data.get("rpo_hours", 0),
            "mtpd_hours": bia_data.get("mtpd_hours", 0),
            "required_recovery_location": "failover_site"
            if bia_data.get("criticality") == "mission_critical"
            else "secondary_site",
            "backup_frequency_hours": bia_data.get("rpo_hours", 24) / 4,
            "required_documentation": [
                "recovery procedures",
                "contact list",
                "data inventory",
                "dependency map",
            ],
        }

    def prioritize_recovery_order(self, assets: list[dict]) -> list[dict]:
        """
        Prioritize recovery order for business continuity.

        Args:
            assets: List of asset BIA assessments

        Returns:
            Prioritized list of assets for recovery
        """
        # Score based on criticality and impact
        scored_assets = []

        for asset in assets:
            criticality_map = {
                "mission_critical": 100,
                "business_critical": 90,
                "important": 70,
                "supporting": 50,
                "non_essential": 10,
            }

            criticality_score = criticality_map.get(asset.get("criticality"), 50)
            financial_impact = asset.get("financial_impact_per_hour_usd", 0)
            rto = asset.get("rto_hours", 24)

            # Priority score
            priority = (criticality_score * 0.5 + (financial_impact / 1000) * 0.3
                       + (1 / (rto + 1)) * 100 * 0.2)

            scored_assets.append(
                {
                    "asset": asset.get("asset_name"),
                    "priority_score": priority,
                    "criticality": asset.get("criticality"),
                    "rto_hours": rto,
                }
            )

        # Sort by priority (descending)
        return sorted(scored_assets, key=lambda x: x["priority_score"], reverse=True)
