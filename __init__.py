"""
AWS Well-Architected Advisor - Enterprise Modules
Comprehensive cloud architecture, FinOps, compliance, and migration planning
"""

# EKS Modernization Module
try:
    from .eks_modernization import (
        render_modernization_planner,
        EKS_TOOLS_CATALOG,
        CICD_MATURITY_MODEL
    )
    EKS_MODULE_AVAILABLE = True
except ImportError:
    EKS_MODULE_AVAILABLE = False

# FinOps Module
try:
    from .finops_module import (
        render_finops_module,
        FINOPS_MATURITY_MODEL,
        COST_CATEGORIES
    )
    FINOPS_MODULE_AVAILABLE = True
except ImportError:
    FINOPS_MODULE_AVAILABLE = False

# Compliance Module
try:
    from .compliance_module import (
        render_compliance_module,
        COMPLIANCE_FRAMEWORKS,
        AWS_COMPLIANCE_CONTROLS
    )
    COMPLIANCE_MODULE_AVAILABLE = True
except ImportError:
    COMPLIANCE_MODULE_AVAILABLE = False

# Migration & DR Module
try:
    from .migration_dr_module import (
        render_migration_dr_module,
        MIGRATION_STRATEGIES,
        DR_PATTERNS,
        BIA_LEVELS
    )
    MIGRATION_DR_MODULE_AVAILABLE = True
except ImportError:
    MIGRATION_DR_MODULE_AVAILABLE = False

# AWS Organization Connector Module
try:
    from .aws_connector import (
        AWSOrganizationConnector,
        AWSSessionManager,
        render_aws_connector_module,
        AWS_REGIONS
    )
    AWS_CONNECTOR_AVAILABLE = True
except ImportError:
    AWS_CONNECTOR_AVAILABLE = False

# Secrets Helper Module
try:
    from .secrets_helper import (
        get_anthropic_api_key,
        get_aws_credentials,
        get_aws_organization_config,
        check_secrets_configured,
        render_secrets_status
    )
    SECRETS_HELPER_AVAILABLE = True
except ImportError:
    SECRETS_HELPER_AVAILABLE = False

# Multi-Account WAR Scanner Module
try:
    from .war_scanner import (
        render_multi_account_war_scanner,
        WAR_ASSESSMENT_AREAS
    )
    WAR_SCANNER_AVAILABLE = True
except ImportError:
    WAR_SCANNER_AVAILABLE = False

# One-Touch Landscape Scanner Module
try:
    from .landscape_scanner import (
        render_one_touch_scanner,
        AWSLandscapeScanner,
        LandscapeAssessment
    )
    LANDSCAPE_SCANNER_AVAILABLE = True
except ImportError:
    LANDSCAPE_SCANNER_AVAILABLE = False

# PDF Report Generator Module
try:
    from .pdf_report_generator import generate_waf_pdf_report
    PDF_GENERATOR_AVAILABLE = True
except ImportError:
    PDF_GENERATOR_AVAILABLE = False

__all__ = [
    # EKS Module
    'render_modernization_planner',
    'EKS_TOOLS_CATALOG',
    'CICD_MATURITY_MODEL',
    'EKS_MODULE_AVAILABLE',
    # FinOps Module
    'render_finops_module',
    'FINOPS_MATURITY_MODEL',
    'COST_CATEGORIES',
    'FINOPS_MODULE_AVAILABLE',
    # Compliance Module
    'render_compliance_module',
    'COMPLIANCE_FRAMEWORKS',
    'AWS_COMPLIANCE_CONTROLS',
    'COMPLIANCE_MODULE_AVAILABLE',
    # Migration & DR Module
    'render_migration_dr_module',
    'MIGRATION_STRATEGIES',
    'DR_PATTERNS',
    'BIA_LEVELS',
    'MIGRATION_DR_MODULE_AVAILABLE',
    # AWS Connector Module
    'AWSOrganizationConnector',
    'AWSSessionManager',
    'render_aws_connector_module',
    'AWS_REGIONS',
    'AWS_CONNECTOR_AVAILABLE',
    # Secrets Helper Module
    'get_anthropic_api_key',
    'get_aws_credentials',
    'get_aws_organization_config',
    'check_secrets_configured',
    'render_secrets_status',
    'SECRETS_HELPER_AVAILABLE',
    # WAR Scanner Module
    'render_multi_account_war_scanner',
    'WAR_ASSESSMENT_AREAS',
    'WAR_SCANNER_AVAILABLE',
    # Landscape Scanner Module
    'render_one_touch_scanner',
    'AWSLandscapeScanner',
    'LandscapeAssessment',
    'LANDSCAPE_SCANNER_AVAILABLE',
    # PDF Generator Module
    'generate_waf_pdf_report',
    'PDF_GENERATOR_AVAILABLE'
]

