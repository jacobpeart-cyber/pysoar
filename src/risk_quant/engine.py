"""Risk Quantification Engine

Implements FAIR (Factor Analysis of Information Risk) Monte Carlo simulation
and advanced risk analytics.

Simulation model (``FAIREngine.run_simulation``), one draw per iteration:

* every analyst estimate is a three-point (min, most likely, max) estimate
  sampled from the standard PERT distribution: Beta(alpha, beta) scaled to
  [min, max] with alpha = 1 + 4 (mode - min) / (max - min) and
  beta = 1 + 4 (max - mode) / (max - min) (lambda = 4). The previous sampler
  used p = (mu - min) / range, q = (max - mu) / range, which sum to 1 and give
  a U-shaped Beta: the mean survived but every percentile and the
  loss-exceedance curve were distorted;
* Threat Event Frequency TEF ~ PERT(tef) events per year;
* Vulnerability V ~ PERT(vuln): the analyst's direct estimate of the
  probability that a threat event becomes a loss event (FAIR allows estimating
  Vulnerability directly). Threat Capability and Resistance Strength are
  stored as the supporting estimates and the result reports
  ``derived_vulnerability`` = share of draws where TCap > RS, so an analyst can
  see when the two disagree; they are not multiplied into the model (the old
  ``TCap * (1 - RS)`` product is not a FAIR quantity);
* Loss Event Frequency LEF = TEF * V;
* the number of loss events in the simulated year N ~ Poisson(LEF);
* each loss event costs LM = PL + SLEF * SL with PL ~ PERT(primary_loss),
  SL ~ PERT(secondary_loss) and SLEF the stored secondary loss event
  frequency (0-1). The stored ``lm_*`` triple is the analyst's overall
  per-event estimate and is reported, not sampled, because primary and
  secondary loss already define LM;
* annual loss = sum of the N event losses (exact compound sampling while the
  total number of events stays under ``MAX_COMPOUND_EVENTS``; above that the
  year's loss is N times one LM draw and ``approximation`` says so).

So ``ale_mean`` estimates E[LEF] * E[LM] and the percentiles / exceedance
curve describe the distribution of a year's total loss. A per-analysis seed
makes a run reproducible, so the stored figures and a portfolio re-simulation
from the same stored inputs agree.

No input is ever defaulted: ``validate_fair_inputs`` names the first missing
or inconsistent estimate and callers turn that into a 422.
"""

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any, Optional

import numpy as np

from src.core.logging import get_logger

logger = get_logger(__name__)

#: Three-point estimates the simulation validates, with their upper bound.
FAIR_TRIPLES: tuple[tuple[str, Optional[float]], ...] = (
    ("tef", None),
    ("vuln", 1.0),
    ("tcap", 1.0),
    ("rs", 1.0),
    ("lm", None),
    ("primary_loss", None),
    ("secondary_loss", None),
)

#: Above this many simulated loss events the per-event compound sum is
#: replaced by N x one LM draw (memory bound: one float per event).
MAX_COMPOUND_EVENTS = 2_000_000


class FAIRInputError(ValueError):
    """A FAIR input is missing or inconsistent; ``field`` names it."""

    def __init__(self, field_name: str, detail: str):
        super().__init__(f"{field_name}: {detail}")
        self.field = field_name
        self.detail = detail


def validate_fair_inputs(data: Any) -> None:
    """Raise FAIRInputError for the first missing or inconsistent input.

    ``data`` is a mapping or an object with the FAIRAnalysis attributes. Every
    triple needs min <= mode <= max, all >= 0 (probabilities <= 1), and
    ``secondary_loss_event_frequency`` must be stored in [0, 1].
    """

    def _get(name: str) -> Any:
        if isinstance(data, dict):
            return data.get(name)
        return getattr(data, name, None)

    for prefix, upper in FAIR_TRIPLES:
        values = []
        for part in ("min", "mode", "max"):
            name = f"{prefix}_{part}"
            raw = _get(name)
            if raw is None:
                raise FAIRInputError(name, "is required (no default is assumed)")
            try:
                value = float(raw)
            except (TypeError, ValueError):
                raise FAIRInputError(name, "must be a number") from None
            if math.isnan(value) or math.isinf(value):
                raise FAIRInputError(name, "must be a finite number")
            if value < 0 or (upper is not None and value > upper):
                bound = f"between 0 and {upper:g}" if upper is not None else ">= 0"
                raise FAIRInputError(name, f"must be {bound}")
            values.append(value)
        lo, mode, hi = values
        if not lo <= mode <= hi:
            raise FAIRInputError(
                f"{prefix}_mode",
                f"{prefix} needs min <= mode <= max (got {lo:g} / {mode:g} / {hi:g})",
            )
    slef = _get("secondary_loss_event_frequency")
    if slef is None:
        raise FAIRInputError("secondary_loss_event_frequency", "is required (no default is assumed)")
    try:
        slef_value = float(slef)
    except (TypeError, ValueError):
        raise FAIRInputError("secondary_loss_event_frequency", "must be a number") from None
    if not 0 <= slef_value <= 1:
        raise FAIRInputError("secondary_loss_event_frequency", "must be between 0 and 1")


def analysis_inputs(analysis: Any) -> dict[str, float]:
    """The stored inputs of a FAIRAnalysis row as a plain dict (validated)."""
    validate_fair_inputs(analysis)
    out: dict[str, float] = {}
    for prefix, _upper in FAIR_TRIPLES:
        for part in ("min", "mode", "max"):
            name = f"{prefix}_{part}"
            out[name] = float(getattr(analysis, name))
    out["secondary_loss_event_frequency"] = float(analysis.secondary_loss_event_frequency)
    return out


def analysis_seed(analysis_id: str) -> int:
    """Deterministic RNG seed for an analysis (stable across runs)."""
    return int(hashlib.sha256(str(analysis_id).encode("utf-8")).hexdigest()[:12], 16)


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
    derived_vulnerability: float = 0.0
    iterations: int = 0
    approximation: Optional[str] = None
    model: dict = field(default_factory=dict)


class FAIREngine:
    """FAIR Model Monte Carlo simulation engine (see the module docstring)."""

    def __init__(self, seed: Optional[int] = None):
        """Initialize FAIR engine; ``seed`` makes a run reproducible."""
        self.logger = logger
        self.rng = np.random.default_rng(seed)

    def sample_pert_distribution(
        self, min_val: float, mode_val: float, max_val: float, size: int = 1
    ) -> np.ndarray:
        """Sample the standard PERT distribution on [min_val, max_val].

        alpha = 1 + 4 (mode - min) / range, beta = 1 + 4 (max - mode) / range;
        the mean is (min + 4 mode + max) / 6. A degenerate estimate
        (min == max) is the constant. Raises ValueError for an inconsistent
        triple instead of silently swapping in another distribution.
        """
        min_val, mode_val, max_val = float(min_val), float(mode_val), float(max_val)
        if not min_val <= mode_val <= max_val:
            raise ValueError(f"PERT needs min <= mode <= max, got {min_val}/{mode_val}/{max_val}")
        range_val = max_val - min_val
        if range_val <= 0:
            return np.full(size, min_val)
        alpha = 1.0 + 4.0 * (mode_val - min_val) / range_val
        beta_shape = 1.0 + 4.0 * (max_val - mode_val) / range_val
        return min_val + self.rng.beta(alpha, beta_shape, size=size) * range_val

    def calculate_tef(self, tef_params: dict, iterations: int = 10000) -> np.ndarray:
        """Threat Event Frequency samples (events per year)."""
        tef = self.sample_pert_distribution(
            tef_params["min"], tef_params["mode"], tef_params["max"], size=iterations
        )
        return np.maximum(tef, 0)

    def calculate_vulnerability(
        self,
        tcap_samples: np.ndarray,
        rs_samples: np.ndarray,
    ) -> np.ndarray:
        """Per-draw indicator that Threat Capability exceeds Resistance Strength.

        Its mean is the FAIR derivation P(TCap > RS); the simulation reports it
        as ``derived_vulnerability`` next to the analyst's direct estimate.
        """
        return (np.asarray(tcap_samples) > np.asarray(rs_samples)).astype(float)

    def calculate_lef(
        self,
        tef_samples: np.ndarray,
        vuln_samples: np.ndarray,
    ) -> np.ndarray:
        """Loss Event Frequency LEF = TEF x Vulnerability (events per year)."""
        return np.maximum(tef_samples * vuln_samples, 0)

    def calculate_loss_magnitude(
        self,
        primary_samples: np.ndarray,
        secondary_samples: np.ndarray,
        secondary_lef_samples: np.ndarray,
    ) -> np.ndarray:
        """Loss per event LM = Primary + Secondary x Secondary LEF."""
        return np.maximum(primary_samples + (secondary_samples * secondary_lef_samples), 0)

    def calculate_ale(
        self,
        lef_samples: np.ndarray,
        lm_samples: np.ndarray,
    ) -> np.ndarray:
        """Expected annual loss per parameter draw, LEF x LM."""
        return np.maximum(lef_samples * lm_samples, 0)

    def _annual_losses(
        self,
        lef: np.ndarray,
        primary: tuple[float, float, float],
        secondary: tuple[float, float, float],
        slef: float,
    ) -> tuple[np.ndarray, np.ndarray, Optional[str]]:
        """Compound annual loss: N ~ Poisson(LEF) events, each with a fresh LM draw."""
        iterations = len(lef)
        events = self.rng.poisson(lef)
        total_events = int(events.sum())

        def _lm(size: int) -> np.ndarray:
            pl = np.maximum(self.sample_pert_distribution(*primary, size=size), 0)
            sl = np.maximum(self.sample_pert_distribution(*secondary, size=size), 0)
            return self.calculate_loss_magnitude(pl, sl, np.full(size, slef))

        lm_per_year = _lm(iterations)  # one representative LM per draw (reported)
        if total_events == 0:
            return np.zeros(iterations), lm_per_year, None
        if total_events > MAX_COMPOUND_EVENTS:
            return events * lm_per_year, lm_per_year, "events_share_one_magnitude_per_year"
        event_losses = _lm(total_events)
        annual = np.zeros(iterations)
        nonzero = np.nonzero(events)[0]
        starts = np.concatenate(([0], np.cumsum(events[nonzero])[:-1])).astype(np.int64)
        annual[nonzero] = np.add.reduceat(event_losses, starts)
        return annual, lm_per_year, None

    def generate_loss_exceedance_curve(
        self, ale_samples: np.ndarray, num_points: int = 100
    ) -> dict:
        """Loss exceedance curve P(annual loss > x) on an even grid up to the max loss."""
        ale_samples = np.asarray(ale_samples, dtype=float)
        if len(ale_samples) == 0:
            return {"x_values": [], "y_values": []}
        max_loss = float(np.max(ale_samples))
        if max_loss <= 0:
            return {"x_values": [0.0], "y_values": [0.0]}
        thresholds = np.linspace(0, max_loss, num_points)
        ordered = np.sort(ale_samples)
        n = len(ordered)
        exceed = n - np.searchsorted(ordered, thresholds, side="right")
        return {
            "x_values": [float(x) for x in thresholds],
            "y_values": [float(c) / n for c in exceed],
        }

    def run_simulation(self, analysis_data: dict, iterations: int = 10000) -> FAIRAnalysisResult:
        """Run the FAIR Monte Carlo simulation over stored inputs.

        ``analysis_data`` must carry every triple in ``FAIR_TRIPLES`` and
        ``secondary_loss_event_frequency``; a missing or inconsistent value
        raises FAIRInputError naming it (nothing is defaulted).
        """
        validate_fair_inputs(analysis_data)
        iterations = int(iterations)
        if iterations < 1:
            raise FAIRInputError("simulation_iterations", "must be at least 1")

        def _triple(prefix: str) -> tuple[float, float, float]:
            return (
                float(analysis_data[f"{prefix}_min"]),
                float(analysis_data[f"{prefix}_mode"]),
                float(analysis_data[f"{prefix}_max"]),
            )

        tef_samples = np.maximum(self.sample_pert_distribution(*_triple("tef"), size=iterations), 0)
        vuln_samples = np.clip(self.sample_pert_distribution(*_triple("vuln"), size=iterations), 0, 1)
        tcap_samples = self.sample_pert_distribution(*_triple("tcap"), size=iterations)
        rs_samples = self.sample_pert_distribution(*_triple("rs"), size=iterations)
        derived_vulnerability = float(np.mean(self.calculate_vulnerability(tcap_samples, rs_samples)))

        lef_samples = self.calculate_lef(tef_samples, vuln_samples)
        ale_samples, lm_samples, approximation = self._annual_losses(
            lef_samples,
            _triple("primary_loss"),
            _triple("secondary_loss"),
            float(analysis_data["secondary_loss_event_frequency"]),
        )

        ale_mean = float(np.mean(ale_samples))
        p10, p50, p90, p99 = (float(v) for v in np.percentile(ale_samples, [10, 50, 90, 99]))

        self.logger.info(
            "fair_simulation_completed",
            iterations=iterations,
            ale_mean=ale_mean,
            ale_p50=p50,
        )

        return FAIRAnalysisResult(
            ale_mean=ale_mean,
            ale_p10=p10,
            ale_p50=p50,
            ale_p90=p90,
            ale_p99=p99,
            loss_exceedance_curve=self.generate_loss_exceedance_curve(ale_samples),
            tef_distribution=tef_samples.tolist(),
            vuln_distribution=vuln_samples.tolist(),
            lef_distribution=lef_samples.tolist(),
            lm_distribution=lm_samples.tolist(),
            ale_distribution=ale_samples.tolist(),
            derived_vulnerability=derived_vulnerability,
            iterations=iterations,
            approximation=approximation,
            model=dict(FAIR_MODEL_DESCRIPTION),
        )

    def generate_risk_report(self, analysis_result: FAIRAnalysisResult) -> dict:
        """Summary statistics of a simulation (terciles of the simulated annual loss)."""
        ale_dist = np.array(analysis_result.ale_distribution)
        q33, q67 = np.percentile(ale_dist, [33, 67])

        return {
            "ale_statistics": {
                "mean": analysis_result.ale_mean,
                "median": analysis_result.ale_p50,
                "p10": analysis_result.ale_p10,
                "p90": analysis_result.ale_p90,
                "p99": analysis_result.ale_p99,
                "std_dev": float(np.std(ale_dist)),
                "min": float(np.min(ale_dist)),
                "max": float(np.max(ale_dist)),
                "derived_vulnerability": analysis_result.derived_vulnerability,
                "iterations": analysis_result.iterations,
                "approximation": analysis_result.approximation,
            },
            "loss_exceedance_curve": analysis_result.loss_exceedance_curve,
            "risk_distribution": {
                "low_risk_count": int(np.sum(ale_dist < q33)),
                "medium_risk_count": int(np.sum((ale_dist >= q33) & (ale_dist < q67))),
                "high_risk_count": int(np.sum(ale_dist >= q67)),
            },
        }


#: What the simulation does, returned with every result so a reader of the
#: figures knows which stored inputs drove them.
FAIR_MODEL_DESCRIPTION: dict[str, Any] = {
    "distribution": "pert (lambda 4)",
    "vulnerability_source": "vuln_min/vuln_mode/vuln_max",
    "loss_events_per_year": "poisson(tef x vuln)",
    "loss_per_event": "primary_loss + secondary_loss_event_frequency x secondary_loss",
    "reported_not_sampled": ["tcap", "rs", "lm"],
}


def simulate_analysis(analysis: Any, iterations: Optional[int] = None) -> FAIRAnalysisResult:
    """Simulate a stored FAIRAnalysis row with its own deterministic seed."""
    inputs = analysis_inputs(analysis)
    runs = int(iterations or analysis.simulation_iterations or 0)
    if runs < 1:
        raise FAIRInputError("simulation_iterations", "is required (no default is assumed)")
    return FAIREngine(seed=analysis_seed(analysis.id)).run_simulation(inputs, runs)


def store_result(analysis: Any, result: FAIRAnalysisResult, completed_at: Any) -> None:
    """Write a simulation result onto its FAIRAnalysis row."""
    analysis.ale_mean = result.ale_mean
    analysis.ale_p10 = result.ale_p10
    analysis.ale_p50 = result.ale_p50
    analysis.ale_p90 = result.ale_p90
    analysis.ale_p99 = result.ale_p99
    analysis.loss_exceedance_curve = json.dumps(result.loss_exceedance_curve)
    analysis.completed_at = completed_at


#: Probability grid of the portfolio loss-exceedance curve.
PORTFOLIO_GRID = tuple(round(i * 0.05, 2) for i in range(21))


def simulate_portfolio(analyses: list[Any], iterations: int = 10000) -> dict[str, Any]:
    """Portfolio annual loss from stored analyses, assuming independent scenarios.

    Each analysis is re-simulated from its stored inputs with its own seed and
    a common iteration count; the portfolio loss of draw i is the sum of the
    scenarios' draw-i losses. Percentiles, VaR and the exceedance curve come
    from that summed distribution (summing per-scenario percentiles would
    assume perfectly correlated scenarios and overstate the tail).
    """
    if not analyses:
        return {"iterations": 0, "samples": np.zeros(0)}
    total = np.zeros(iterations)
    for analysis in analyses:
        total += np.asarray(simulate_analysis(analysis, iterations).ale_distribution)
    p50, p90, p95, p99 = (float(v) for v in np.percentile(total, [50, 90, 95, 99]))
    curve = [
        {"probability": p, "loss": round(float(np.quantile(total, 1.0 - p)), 2)}
        for p in PORTFOLIO_GRID
    ]
    return {
        "iterations": iterations,
        "samples": total,
        "mean": float(np.mean(total)),
        "p50": p50,
        "p90": p90,
        "p95": p95,
        "p99": p99,
        "curve": curve,
    }


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
        if len({len(s) for s in ale_samples}) != 1:
            raise ValueError("portfolio VaR needs the same number of draws per risk")

        # Sum across risks for each iteration (independent risks)
        portfolio_losses = np.sum(np.array(ale_samples), axis=0)

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

        # No benefit means the control never pays back: None, not inf (inf is
        # not valid JSON and turned the audit route into a 500).
        payback_months = (
            (annual_control_cost / annual_benefit) * 12
            if annual_benefit > 0
            else None
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
