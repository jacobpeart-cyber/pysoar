"""
PySOAR SIEM Engine
==================
Built-in Security Information and Event Management engine providing
log ingestion, parsing, normalization, detection rules, correlation,
and search capabilities without external dependencies like Elasticsearch.

Modules:
    - models: SQLAlchemy models for log entries, detection rules, correlations
    - parser: Log parsing with regex/grok patterns for syslog, JSON, CEF, LEEF
    - normalizer: Map vendor-specific fields to common schema
    - storage: Time-series log storage with PostgreSQL partitioning and retention
    - rules: Sigma-inspired YAML detection rule engine
    - correlation: Event correlation and multi-stage attack detection
    - search: Full-text and field-based log search
"""
