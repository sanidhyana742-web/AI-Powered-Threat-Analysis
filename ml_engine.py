import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestRegressor

def load_dataset():
    try:
        project_dir = os.path.dirname(os.path.abspath(__file__))
        dataset_path = os.path.join(project_dir, 'dataset', 'national_critical_infrastructure_risk_dataset_10000.csv')
        df = pd.read_csv(dataset_path)
        return df
    except Exception as e:
        # Fallback dummy frame if file missing during startup
        return pd.DataFrame()

def compute_analytics():
    df = load_dataset()
    if df.empty:
        return {}

    total_records = len(df)
    critical_count = len(df[df['severity'] == 'CRITICAL'])
    avg_risk = round(df['risk_score'].mean(), 1)
    
    sector_summary = df.groupby('sector')['risk_score'].mean().round(1).to_dict()
    attack_summary = df['attack_type'].value_counts().head(5).to_dict()

    return {
        "total_records": total_records,
        "critical_count": critical_count,
        "avg_risk": avg_risk,
        "sector_summary": sector_summary,
        "attack_summary": attack_summary
    }

def get_xai_explanation():
    # Mock SHAP feature importance output based on dynamic risk model
    return {
        "features": ["CVSS Score", "Asset Criticality", "Exploitability Score", "Known Exploited", "Sector Criticality"],
        "importance": [0.38, 0.25, 0.18, 0.11, 0.08]
    }

def generate_synthetic_attacks(count=8, sector="All sectors", intensity="Balanced", seed=None):
    """Generate abstract attack telemetry for defensive testing and model evaluation."""
    df = load_dataset()
    if df.empty:
        return {"records": [], "summary": {"count": 0, "avg_risk": 0, "critical": 0}}

    count = max(1, min(int(count), 50))
    filtered = df if sector == "All sectors" else df[df["sector"] == sector]
    if filtered.empty:
        filtered = df

    rng = np.random.default_rng(seed)
    samples = filtered.iloc[rng.integers(0, len(filtered), size=count)].copy().reset_index(drop=True)
    intensity_factor = {"Low": 0.82, "Balanced": 1.0, "High": 1.16}.get(intensity, 1.0)

    numeric_columns = [
        "cvss_score", "exploitability_score", "threat_confidence",
        "sector_criticality", "asset_criticality", "exposure_score", "risk_score",
    ]
    for column in numeric_columns:
        if column in samples:
            variation = rng.normal(0, 0.08, count) * intensity_factor
            samples[column] = pd.to_numeric(samples[column], errors="coerce").fillna(0) * (1 + variation)

    samples["cvss_score"] = samples["cvss_score"].clip(0, 10).round(1)
    samples["exploitability_score"] = samples["exploitability_score"].clip(0, 10).round(1)
    samples["threat_confidence"] = samples["threat_confidence"].clip(0, 1).round(2)
    samples["sector_criticality"] = samples["sector_criticality"].clip(1, 10).round(1)
    samples["asset_criticality"] = samples["asset_criticality"].clip(1, 10).round(1)
    samples["exposure_score"] = samples["exposure_score"].clip(0, 10).round(1)
    samples["risk_score"] = samples["risk_score"].clip(0, 100).round().astype(int)
    samples["risk_level"] = pd.cut(samples["risk_score"], bins=[-1, 39, 69, 84, 100], labels=["LOW", "MEDIUM", "HIGH", "CRITICAL"]).astype(str)
    samples["record_id"] = [f"GAN-{index:04d}" for index in range(1, count + 1)]
    samples["cve_id"] = [f"SYN-GAN-{rng.integers(2024, 2027)}-{rng.integers(1000, 99999)}" for _ in range(count)]
    samples["known_exploited"] = samples["known_exploited"].astype(bool)
    samples["threat_active"] = samples["threat_active"].astype(bool)

    fields = ["record_id", "cve_id", "sector", "affected_asset", "attack_type", "mitre_technique", "severity", "cvss_score", "exploitability_score", "known_exploited", "threat_active", "threat_confidence", "sector_criticality", "asset_criticality", "exposure_score", "risk_score", "risk_level", "recommended_action"]
    records = samples[fields].to_dict(orient="records")
    return {
        "records": records,
        "summary": {
            "count": count,
            "avg_risk": round(float(samples["risk_score"].mean()), 1),
            "critical": int((samples["risk_level"] == "CRITICAL").sum()),
            "active": int(samples["threat_active"].sum()),
        },
    }