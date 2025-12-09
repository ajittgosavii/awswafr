"""
AWS Well-Architected Framework Advisor
Powered by Anthropic Claude AI

Enterprise-grade architecture review tool that analyzes AWS designs
and provides risk assessments with actionable recommendations.
"""

import streamlit as st
import anthropic
import json
import base64
from datetime import datetime
from typing import Optional, Dict, List, Any
import re
import sys
import os
from pathlib import Path

# CRITICAL: Add the app directory to Python path FIRST
# This ensures modules can be found when running from any directory
APP_DIR = Path(__file__).parent.absolute()
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

# Also ensure we're in the right working directory
os.chdir(APP_DIR)

# Debug info (can be enabled via secrets or environment)
DEBUG_MODE = os.environ.get('DEBUG', 'false').lower() == 'true'
try:
    DEBUG_MODE = DEBUG_MODE or st.secrets.get('DEBUG', False)
except:
    pass

# Check that modules directory exists
MODULES_DIR = APP_DIR / 'modules'
MODULES_EXIST = MODULES_DIR.exists()

# Track module import errors for debugging
MODULE_IMPORT_ERRORS = {}

if not MODULES_EXIST:
    MODULE_IMPORT_ERRORS['_system'] = f"modules directory not found at {MODULES_DIR}. Contents of {APP_DIR}: {list(APP_DIR.iterdir())}"

def safe_import(module_name, from_list):
    """Safely import a module with detailed error reporting"""
    try:
        import importlib
        module = importlib.import_module(f'modules.{module_name}')
        results = {}
        for name in from_list:
            if hasattr(module, name):
                results[name] = getattr(module, name)
            else:
                raise ImportError(f"'{name}' not found in modules.{module_name}")
        return True, results, None
    except Exception as e:
        import traceback
        return False, {}, f"{type(e).__name__}: {str(e)}"

# Import modernization module
MODERNIZATION_AVAILABLE, _mod, _err = safe_import('eks_modernization', ['render_modernization_planner'])
if MODERNIZATION_AVAILABLE:
    render_modernization_planner = _mod['render_modernization_planner']
else:
    MODULE_IMPORT_ERRORS['eks_modernization'] = _err

# Import FinOps module
FINOPS_AVAILABLE, _mod, _err = safe_import('finops_module', ['render_finops_module'])
if FINOPS_AVAILABLE:
    render_finops_module = _mod['render_finops_module']
else:
    MODULE_IMPORT_ERRORS['finops_module'] = _err

# Import Compliance module
COMPLIANCE_AVAILABLE, _mod, _err = safe_import('compliance_module', ['render_compliance_module'])
if COMPLIANCE_AVAILABLE:
    render_compliance_module = _mod['render_compliance_module']
else:
    MODULE_IMPORT_ERRORS['compliance_module'] = _err

# Import Migration & DR module
MIGRATION_DR_AVAILABLE, _mod, _err = safe_import('migration_dr_module', ['render_migration_dr_module'])
if MIGRATION_DR_AVAILABLE:
    render_migration_dr_module = _mod['render_migration_dr_module']
else:
    MODULE_IMPORT_ERRORS['migration_dr_module'] = _err

# Import AWS Connector module
AWS_CONNECTOR_AVAILABLE, _mod, _err = safe_import('aws_connector', ['render_aws_connector_module'])
if AWS_CONNECTOR_AVAILABLE:
    render_aws_connector_module = _mod['render_aws_connector_module']
else:
    MODULE_IMPORT_ERRORS['aws_connector'] = _err

# Import Multi-Account WAR Scanner module
WAR_SCANNER_AVAILABLE, _mod, _err = safe_import('war_scanner', ['render_multi_account_war_scanner'])
if WAR_SCANNER_AVAILABLE:
    render_multi_account_war_scanner = _mod['render_multi_account_war_scanner']
else:
    MODULE_IMPORT_ERRORS['war_scanner'] = _err

# Import One-Touch Landscape Scanner module
LANDSCAPE_SCANNER_AVAILABLE, _mod, _err = safe_import('landscape_scanner', ['render_one_touch_scanner'])
if LANDSCAPE_SCANNER_AVAILABLE:
    render_one_touch_scanner = _mod['render_one_touch_scanner']
else:
    MODULE_IMPORT_ERRORS['landscape_scanner'] = _err

# Page Configuration
st.set_page_config(
    page_title="AWS Well-Architected Advisor",
    page_icon="🏗️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Professional UI
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Source+Sans+Pro:wght@300;400;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    :root {
        --aws-orange: #FF9900;
        --aws-dark: #232F3E;
        --aws-light: #37475A;
        --risk-critical: #D32F2F;
        --risk-high: #F57C00;
        --risk-medium: #FBC02D;
        --risk-low: #388E3C;
        --risk-info: #1976D2;
    }
    
    .main-header {
        background: linear-gradient(135deg, var(--aws-dark) 0%, var(--aws-light) 100%);
        padding: 2rem;
        border-radius: 12px;
        margin-bottom: 2rem;
        box-shadow: 0 4px 20px rgba(0,0,0,0.15);
    }
    
    .main-header h1 {
        color: white;
        font-family: 'Source Sans Pro', sans-serif;
        font-weight: 700;
        margin: 0;
        font-size: 2.2rem;
    }
    
    .main-header p {
        color: var(--aws-orange);
        font-family: 'Source Sans Pro', sans-serif;
        margin: 0.5rem 0 0 0;
        font-size: 1.1rem;
    }
    
    .pillar-card {
        background: white;
        border-radius: 10px;
        padding: 1.2rem;
        margin: 0.5rem 0;
        box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        border-left: 4px solid var(--aws-orange);
        transition: transform 0.2s, box-shadow 0.2s;
    }
    
    .pillar-card:hover {
        transform: translateX(5px);
        box-shadow: 0 4px 15px rgba(0,0,0,0.12);
    }
    
    .risk-badge {
        display: inline-block;
        padding: 0.3rem 0.8rem;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .risk-critical { background: var(--risk-critical); color: white; }
    .risk-high { background: var(--risk-high); color: white; }
    .risk-medium { background: var(--risk-medium); color: #333; }
    .risk-low { background: var(--risk-low); color: white; }
    .risk-info { background: var(--risk-info); color: white; }
    
    .recommendation-box {
        background: #f8f9fa;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        border-left: 3px solid var(--aws-orange);
    }
    
    .metrics-container {
        display: flex;
        gap: 1rem;
        flex-wrap: wrap;
    }
    
    .metric-card {
        flex: 1;
        min-width: 150px;
        background: white;
        border-radius: 10px;
        padding: 1.2rem;
        text-align: center;
        box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }
    
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
    }
    
    .metric-label {
        color: #666;
        font-size: 0.9rem;
        margin-top: 0.3rem;
    }
    
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        background: white;
        border-radius: 8px 8px 0 0;
        padding: 0.5rem 1.5rem;
        font-weight: 600;
    }
    
    .stTabs [aria-selected="true"] {
        background: var(--aws-orange) !important;
        color: white !important;
    }
    
    .finding-item {
        background: white;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.8rem 0;
        box-shadow: 0 1px 4px rgba(0,0,0,0.1);
    }
    
    .code-block {
        background: #1e1e1e;
        color: #d4d4d4;
        padding: 1rem;
        border-radius: 8px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        overflow-x: auto;
    }
    
    .sidebar-info {
        background: linear-gradient(135deg, #f5f7fa 0%, #e4e8ec 100%);
        border-radius: 10px;
        padding: 1rem;
        margin: 1rem 0;
    }
    
    .pillar-icon {
        font-size: 1.5rem;
        margin-right: 0.5rem;
    }
    
    .score-ring {
        width: 120px;
        height: 120px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.8rem;
        font-weight: 700;
        margin: 0 auto;
    }
    
    .export-btn {
        background: var(--aws-orange);
        color: white;
        border: none;
        padding: 0.6rem 1.5rem;
        border-radius: 6px;
        cursor: pointer;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# AWS Well-Architected Framework Pillars
WAF_PILLARS = {
    "operational_excellence": {
        "name": "Operational Excellence",
        "icon": "⚙️",
        "color": "#FF9900",
        "description": "Run and monitor systems to deliver business value",
        "focus_areas": [
            "Organization", "Prepare", "Operate", "Evolve"
        ]
    },
    "security": {
        "name": "Security",
        "icon": "🔐",
        "color": "#D32F2F",
        "description": "Protect information, systems, and assets",
        "focus_areas": [
            "Identity & Access Management", "Detection", "Infrastructure Protection",
            "Data Protection", "Incident Response"
        ]
    },
    "reliability": {
        "name": "Reliability",
        "icon": "🛡️",
        "color": "#1976D2",
        "description": "Recover from failures and meet demand",
        "focus_areas": [
            "Foundations", "Workload Architecture", "Change Management", "Failure Management"
        ]
    },
    "performance_efficiency": {
        "name": "Performance Efficiency",
        "icon": "⚡",
        "color": "#7B1FA2",
        "description": "Use computing resources efficiently",
        "focus_areas": [
            "Selection", "Review", "Monitoring", "Trade-offs"
        ]
    },
    "cost_optimization": {
        "name": "Cost Optimization",
        "icon": "💰",
        "color": "#388E3C",
        "description": "Avoid unnecessary costs",
        "focus_areas": [
            "Cloud Financial Management", "Expenditure Awareness",
            "Cost-Effective Resources", "Manage Demand & Supply"
        ]
    },
    "sustainability": {
        "name": "Sustainability",
        "icon": "🌱",
        "color": "#00796B",
        "description": "Minimize environmental impacts",
        "focus_areas": [
            "Region Selection", "Alignment to Demand", "Software & Architecture",
            "Data Management", "Hardware & Services"
        ]
    }
}

# Risk Level Definitions
RISK_LEVELS = {
    "CRITICAL": {"color": "#D32F2F", "priority": 1, "description": "Immediate action required - severe impact"},
    "HIGH": {"color": "#F57C00", "priority": 2, "description": "Address within 1-2 weeks"},
    "MEDIUM": {"color": "#FBC02D", "priority": 3, "description": "Address within 1-3 months"},
    "LOW": {"color": "#388E3C", "priority": 4, "description": "Consider for future improvements"},
    "INFO": {"color": "#1976D2", "priority": 5, "description": "Informational - best practice suggestion"}
}


def init_session_state():
    """Initialize session state variables"""
    defaults = {
        "analysis_results": None,
        "uploaded_content": None,
        "content_type": None,
        "analysis_history": [],
        "custom_questions": [],
        "api_key_valid": False,
        "custom_learnings": [],
        "organization_context": ""
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value
    
    # Check for secrets-based API key - try multiple formats
    if "anthropic_api_key" not in st.session_state or not st.session_state.get("anthropic_api_key"):
        api_key = None
        try:
            # Format 1: Direct ANTHROPIC_API_KEY
            if hasattr(st, 'secrets') and "ANTHROPIC_API_KEY" in st.secrets:
                api_key = st.secrets["ANTHROPIC_API_KEY"]
        except Exception:
            pass
        
        if not api_key:
            try:
                # Format 2: Nested [anthropic] section
                if hasattr(st, 'secrets') and "anthropic" in st.secrets:
                    api_key = st.secrets["anthropic"].get("api_key")
            except Exception:
                pass
        
        if api_key:
            st.session_state.anthropic_api_key = api_key
            st.session_state.api_key_valid = True


def get_anthropic_client() -> Optional[anthropic.Anthropic]:
    """Initialize Anthropic client with API key from secrets or user input"""
    api_key = None
    
    # Try session state first (populated by sidebar or init)
    api_key = st.session_state.get("anthropic_api_key", "")
    
    # If not in session state, try secrets directly
    if not api_key:
        try:
            # Format 1: Direct ANTHROPIC_API_KEY
            if hasattr(st, 'secrets') and "ANTHROPIC_API_KEY" in st.secrets:
                api_key = st.secrets["ANTHROPIC_API_KEY"]
        except Exception:
            pass
    
    if not api_key:
        try:
            # Format 2: Nested [anthropic] section
            if hasattr(st, 'secrets') and "anthropic" in st.secrets:
                api_key = st.secrets["anthropic"].get("api_key")
        except Exception:
            pass
    
    if api_key:
        try:
            client = anthropic.Anthropic(api_key=api_key)
            return client
        except Exception as e:
            st.error(f"Failed to initialize Anthropic client: {e}")
    return None


def encode_image(uploaded_file) -> tuple:
    """Encode uploaded image to base64"""
    bytes_data = uploaded_file.getvalue()
    base64_image = base64.standard_b64encode(bytes_data).decode("utf-8")
    
    # Determine media type
    file_type = uploaded_file.type
    if "png" in file_type:
        media_type = "image/png"
    elif "jpg" in file_type or "jpeg" in file_type:
        media_type = "image/jpeg"
    elif "gif" in file_type:
        media_type = "image/gif"
    elif "webp" in file_type:
        media_type = "image/webp"
    else:
        media_type = "image/png"  # Default
    
    return base64_image, media_type


def build_analysis_prompt(content_type: str, additional_context: str = "") -> str:
    """Build the analysis prompt for Claude"""
    
    pillars_detail = "\n".join([
        f"- **{p['name']}** ({p['icon']}): {p['description']}. Focus areas: {', '.join(p['focus_areas'])}"
        for p in WAF_PILLARS.values()
    ])
    
    prompt = f"""You are an expert AWS Solutions Architect with deep expertise in the AWS Well-Architected Framework. 
Analyze the provided AWS architecture and deliver a comprehensive Well-Architected Review.

## AWS Well-Architected Framework Pillars to Evaluate:
{pillars_detail}

## Risk Classification Criteria:
- **CRITICAL**: Security vulnerabilities, data loss risks, compliance violations, single points of failure in production
- **HIGH**: Performance bottlenecks, cost inefficiencies >30%, missing disaster recovery, inadequate monitoring
- **MEDIUM**: Sub-optimal configurations, minor security gaps, missing automation opportunities
- **LOW**: Best practice deviations, optimization opportunities, documentation gaps
- **INFO**: Suggestions for future improvements, emerging best practices

## Analysis Requirements:

Provide your analysis in the following JSON structure:

```json
{{
    "executive_summary": {{
        "overall_score": <0-100>,
        "maturity_level": "<Initial|Managed|Defined|Quantitatively Managed|Optimizing>",
        "critical_findings_count": <number>,
        "high_findings_count": <number>,
        "medium_findings_count": <number>,
        "low_findings_count": <number>,
        "summary": "<2-3 sentence executive summary>"
    }},
    "pillar_assessments": {{
        "operational_excellence": {{
            "score": <0-100>,
            "findings": [
                {{
                    "risk_level": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
                    "title": "<finding title>",
                    "description": "<detailed description>",
                    "impact": "<business impact>",
                    "recommendation": "<specific actionable recommendation>",
                    "aws_services": ["<relevant AWS services>"],
                    "effort": "<Low|Medium|High>",
                    "cost_impact": "<Increase|Decrease|Neutral>"
                }}
            ]
        }},
        "security": {{ ... same structure ... }},
        "reliability": {{ ... same structure ... }},
        "performance_efficiency": {{ ... same structure ... }},
        "cost_optimization": {{ ... same structure ... }},
        "sustainability": {{ ... same structure ... }}
    }},
    "prioritized_roadmap": [
        {{
            "phase": "<Immediate|Short-term|Medium-term|Long-term>",
            "timeframe": "<e.g., 0-2 weeks>",
            "actions": ["<action items>"],
            "expected_outcomes": ["<outcomes>"]
        }}
    ],
    "architecture_patterns": {{
        "identified_patterns": ["<patterns detected>"],
        "recommended_patterns": ["<patterns to consider>"],
        "anti_patterns": ["<anti-patterns to address>"]
    }},
    "compliance_considerations": {{
        "applicable_frameworks": ["<e.g., SOC2, HIPAA, PCI-DSS>"],
        "gaps": ["<compliance gaps>"],
        "recommendations": ["<compliance recommendations>"]
    }},
    "cost_analysis": {{
        "optimization_opportunities": ["<cost saving opportunities>"],
        "estimated_savings_percentage": <0-100>,
        "rightsizing_recommendations": ["<specific recommendations>"]
    }}
}}
```

{f"Additional Context: {additional_context}" if additional_context else ""}

{f"Organization-Specific Context: {st.session_state.get('organization_context', '')}" if st.session_state.get('organization_context', '') else ""}

Analyze the architecture thoroughly and provide actionable, specific recommendations that an AWS team can implement immediately.
Focus on practical improvements rather than theoretical best practices.
"""
    return prompt


def analyze_architecture(client: anthropic.Anthropic, content: Any, content_type: str, 
                         additional_context: str = "") -> Dict:
    """Send architecture to Claude for analysis"""
    
    prompt = build_analysis_prompt(content_type, additional_context)
    
    # Build message content based on content type
    if content_type == "image":
        base64_image, media_type = content
        message_content = [
            {
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": media_type,
                    "data": base64_image
                }
            },
            {
                "type": "text",
                "text": prompt
            }
        ]
    else:
        # Text-based content (JSON, YAML, or description)
        message_content = [
            {
                "type": "text",
                "text": f"{prompt}\n\n## Architecture Input:\n```\n{content}\n```"
            }
        ]
    
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=8000,
            messages=[
                {
                    "role": "user",
                    "content": message_content
                }
            ]
        )
        
        # Extract JSON from response
        response_text = response.content[0].text
        
        # Try to parse JSON from response
        json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(1))
        else:
            # Try direct JSON parse
            return json.loads(response_text)
            
    except json.JSONDecodeError as e:
        st.error(f"Failed to parse analysis response: {e}")
        return {"error": "Failed to parse response", "raw_response": response_text}
    except Exception as e:
        st.error(f"Analysis failed: {e}")
        return {"error": str(e)}


def render_header():
    """Render the main header"""
    st.markdown("""
    <div class="main-header">
        <h1>🏗️ AWS Well-Architected Framework Advisor</h1>
        <p>AI-Powered Architecture Review & Risk Assessment</p>
    </div>
    """, unsafe_allow_html=True)


def render_sidebar():
    """Render the sidebar with configuration options"""
    with st.sidebar:
        st.markdown("### ⚙️ Configuration")
        
        # Check if API key is in secrets - try multiple formats
        has_secret_key = False
        secret_api_key = None
        
        try:
            # Format 1: Direct ANTHROPIC_API_KEY
            if hasattr(st, 'secrets') and "ANTHROPIC_API_KEY" in st.secrets:
                secret_api_key = st.secrets["ANTHROPIC_API_KEY"]
                has_secret_key = bool(secret_api_key)
        except Exception:
            pass
        
        if not has_secret_key:
            try:
                # Format 2: Nested [anthropic] section
                if hasattr(st, 'secrets') and "anthropic" in st.secrets:
                    secret_api_key = st.secrets["anthropic"].get("api_key")
                    has_secret_key = bool(secret_api_key)
            except Exception:
                pass
        
        if has_secret_key and secret_api_key:
            st.success("✓ API Key configured via secrets")
            st.session_state.api_key_valid = True
            st.session_state.anthropic_api_key = secret_api_key
        else:
            # API Key input
            api_key = st.text_input(
                "Anthropic API Key",
                type="password",
                help="Enter your Anthropic API key to enable AI analysis",
                key="anthropic_api_key_input"
            )
            
            if api_key:
                st.success("✓ API Key configured")
                st.session_state.api_key_valid = True
                st.session_state.anthropic_api_key = api_key
            else:
                st.warning("⚠️ API Key required for analysis")
                st.session_state.api_key_valid = False
        
        st.markdown("---")
        
        # Module Status Section
        st.markdown("### 📦 Module Status")
        
        modules_status = {
            "AWS Connector": AWS_CONNECTOR_AVAILABLE,
            "One-Touch Scanner": LANDSCAPE_SCANNER_AVAILABLE,
            "WAR Scanner": WAR_SCANNER_AVAILABLE,
            "EKS & CI/CD": MODERNIZATION_AVAILABLE,
            "FinOps": FINOPS_AVAILABLE,
            "Compliance": COMPLIANCE_AVAILABLE,
            "Migration & DR": MIGRATION_DR_AVAILABLE
        }
        
        available_count = sum(modules_status.values())
        total_count = len(modules_status)
        
        if available_count == total_count:
            st.success(f"✅ All {total_count} modules loaded")
        else:
            st.warning(f"⚠️ {available_count}/{total_count} modules loaded")
            
            # Show which modules failed
            with st.expander("View module details"):
                for name, available in modules_status.items():
                    if available:
                        st.markdown(f"✅ {name}")
                    else:
                        st.markdown(f"❌ {name}")
                
                # Show import errors if any
                if MODULE_IMPORT_ERRORS:
                    st.markdown("**Import Errors:**")
                    for module, error in MODULE_IMPORT_ERRORS.items():
                        st.code(f"{module}: {error}", language="text")
                
                # Show debug info
                st.markdown("**Debug Info:**")
                st.code(f"APP_DIR: {APP_DIR}\nModules exist: {MODULES_EXIST}\nsys.path[0]: {sys.path[0]}", language="text")
        
        st.markdown("---")
        
        # Organization Context (Custom Learning)
        st.markdown("### 🏢 Organization Context")
        org_context = st.text_area(
            "Custom Context",
            value=st.session_state.get("organization_context", ""),
            placeholder="Add organization-specific context, standards, or requirements that should influence the analysis...",
            height=100,
            help="This context will be included in every analysis to customize recommendations"
        )
        st.session_state.organization_context = org_context
        
        st.markdown("---")
        
        # Pillar Selection
        st.markdown("### 📋 Pillars to Analyze")
        selected_pillars = {}
        for key, pillar in WAF_PILLARS.items():
            selected_pillars[key] = st.checkbox(
                f"{pillar['icon']} {pillar['name']}",
                value=True,
                key=f"pillar_{key}"
            )
        
        st.markdown("---")
        
        # Analysis Options
        st.markdown("### 🎯 Analysis Depth")
        analysis_depth = st.select_slider(
            "Detail Level",
            options=["Quick Scan", "Standard", "Deep Dive"],
            value="Standard"
        )
        
        st.markdown("---")
        
        # Info Box
        st.markdown("""
        <div class="sidebar-info">
            <strong>📚 AWS WAF Pillars</strong><br>
            <small>
            The Well-Architected Framework helps you understand the pros and cons 
            of decisions you make while building systems on AWS.
            </small>
        </div>
        """, unsafe_allow_html=True)
        
        return selected_pillars, analysis_depth


def render_risk_badge(risk_level: str) -> str:
    """Generate HTML for risk badge"""
    return f'<span class="risk-badge risk-{risk_level.lower()}">{risk_level}</span>'


def render_metrics_dashboard(results: Dict):
    """Render the metrics dashboard"""
    if "executive_summary" not in results:
        return
    
    summary = results["executive_summary"]
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        score = summary.get("overall_score", 0)
        color = "#388E3C" if score >= 80 else "#FBC02D" if score >= 60 else "#D32F2F"
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: {color}">{score}</div>
            <div class="metric-label">Overall Score</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #D32F2F">{summary.get('critical_findings_count', 0)}</div>
            <div class="metric-label">Critical</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #F57C00">{summary.get('high_findings_count', 0)}</div>
            <div class="metric-label">High</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #FBC02D">{summary.get('medium_findings_count', 0)}</div>
            <div class="metric-label">Medium</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col5:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #388E3C">{summary.get('low_findings_count', 0)}</div>
            <div class="metric-label">Low</div>
        </div>
        """, unsafe_allow_html=True)


def render_pillar_results(results: Dict):
    """Render detailed pillar assessment results"""
    if "pillar_assessments" not in results:
        return
    
    assessments = results["pillar_assessments"]
    
    tabs = st.tabs([f"{WAF_PILLARS[key]['icon']} {WAF_PILLARS[key]['name']}" 
                    for key in assessments.keys() if key in WAF_PILLARS])
    
    for idx, (pillar_key, assessment) in enumerate(assessments.items()):
        if pillar_key not in WAF_PILLARS:
            continue
            
        pillar = WAF_PILLARS[pillar_key]
        
        with tabs[idx]:
            # Pillar Score
            score = assessment.get("score", 0)
            score_color = "#388E3C" if score >= 80 else "#FBC02D" if score >= 60 else "#D32F2F"
            
            col1, col2 = st.columns([1, 3])
            with col1:
                st.markdown(f"""
                <div style="text-align: center; padding: 1rem;">
                    <div class="score-ring" style="background: linear-gradient(135deg, {score_color}22, {score_color}44); border: 4px solid {score_color};">
                        {score}
                    </div>
                    <div style="margin-top: 0.5rem; color: #666;">Pillar Score</div>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                st.markdown(f"### {pillar['icon']} {pillar['name']}")
                st.markdown(f"*{pillar['description']}*")
                st.markdown(f"**Focus Areas:** {', '.join(pillar['focus_areas'])}")
            
            st.markdown("---")
            
            # Findings
            findings = assessment.get("findings", [])
            if findings:
                st.markdown("#### 📋 Findings")
                
                # Group by risk level
                for risk_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                    level_findings = [f for f in findings if f.get("risk_level") == risk_level]
                    if level_findings:
                        with st.expander(f"{render_risk_badge(risk_level)} {risk_level} ({len(level_findings)})", expanded=(risk_level in ["CRITICAL", "HIGH"])):
                            for finding in level_findings:
                                st.markdown(f"""
                                <div class="finding-item">
                                    <strong>{finding.get('title', 'Finding')}</strong>
                                    <p>{finding.get('description', '')}</p>
                                    <p><strong>Impact:</strong> {finding.get('impact', 'N/A')}</p>
                                    <p><strong>Recommendation:</strong> {finding.get('recommendation', 'N/A')}</p>
                                    <p><strong>Effort:</strong> {finding.get('effort', 'N/A')} | 
                                       <strong>Cost Impact:</strong> {finding.get('cost_impact', 'N/A')}</p>
                                    <p><strong>AWS Services:</strong> {', '.join(finding.get('aws_services', []))}</p>
                                </div>
                                """, unsafe_allow_html=True)
            else:
                st.info("No findings for this pillar.")


def render_roadmap(results: Dict):
    """Render the prioritized implementation roadmap"""
    if "prioritized_roadmap" not in results:
        return
    
    st.markdown("### 🗺️ Prioritized Implementation Roadmap")
    
    roadmap = results["prioritized_roadmap"]
    
    for phase in roadmap:
        phase_name = phase.get("phase", "Unknown")
        timeframe = phase.get("timeframe", "")
        
        # Color coding for phases
        colors = {
            "Immediate": "#D32F2F",
            "Short-term": "#F57C00",
            "Medium-term": "#FBC02D",
            "Long-term": "#388E3C"
        }
        color = colors.get(phase_name, "#1976D2")
        
        with st.expander(f"📅 {phase_name} ({timeframe})", expanded=(phase_name == "Immediate")):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Actions:**")
                for action in phase.get("actions", []):
                    st.markdown(f"- {action}")
            
            with col2:
                st.markdown("**Expected Outcomes:**")
                for outcome in phase.get("expected_outcomes", []):
                    st.markdown(f"- {outcome}")


def render_patterns_analysis(results: Dict):
    """Render architecture patterns analysis"""
    if "architecture_patterns" not in results:
        return
    
    patterns = results["architecture_patterns"]
    
    st.markdown("### 🏛️ Architecture Patterns Analysis")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**✅ Identified Patterns**")
        for pattern in patterns.get("identified_patterns", []):
            st.markdown(f"- {pattern}")
    
    with col2:
        st.markdown("**💡 Recommended Patterns**")
        for pattern in patterns.get("recommended_patterns", []):
            st.markdown(f"- {pattern}")
    
    with col3:
        st.markdown("**⚠️ Anti-Patterns Detected**")
        for pattern in patterns.get("anti_patterns", []):
            st.markdown(f"- {pattern}")


def render_compliance_section(results: Dict):
    """Render compliance considerations"""
    if "compliance_considerations" not in results:
        return
    
    compliance = results["compliance_considerations"]
    
    st.markdown("### 📜 Compliance Considerations")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Applicable Frameworks:**")
        frameworks = compliance.get("applicable_frameworks", [])
        if frameworks:
            st.markdown(" | ".join([f"`{f}`" for f in frameworks]))
        
        st.markdown("**Compliance Gaps:**")
        for gap in compliance.get("gaps", []):
            st.markdown(f"- ⚠️ {gap}")
    
    with col2:
        st.markdown("**Recommendations:**")
        for rec in compliance.get("recommendations", []):
            st.markdown(f"- ✓ {rec}")


def render_cost_analysis(results: Dict):
    """Render cost optimization analysis"""
    if "cost_analysis" not in results:
        return
    
    cost = results["cost_analysis"]
    
    st.markdown("### 💰 Cost Optimization Analysis")
    
    savings = cost.get("estimated_savings_percentage", 0)
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.metric(
            label="Estimated Savings Potential",
            value=f"{savings}%",
            delta="Cost Reduction"
        )
    
    with col2:
        st.markdown("**Optimization Opportunities:**")
        for opp in cost.get("optimization_opportunities", []):
            st.markdown(f"- 💡 {opp}")
        
        st.markdown("**Rightsizing Recommendations:**")
        for rec in cost.get("rightsizing_recommendations", []):
            st.markdown(f"- 📉 {rec}")


def export_results(results: Dict) -> str:
    """Export results to JSON"""
    export_data = {
        "export_date": datetime.now().isoformat(),
        "tool": "AWS Well-Architected Framework Advisor",
        "version": "1.0",
        "analysis_results": results
    }
    return json.dumps(export_data, indent=2)


def generate_markdown_report(results: Dict) -> str:
    """Generate a markdown report from results"""
    if not results or "executive_summary" not in results:
        return "No results to export"
    
    summary = results["executive_summary"]
    
    report = f"""# AWS Well-Architected Framework Review Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Executive Summary

- **Overall Score:** {summary.get('overall_score', 'N/A')}/100
- **Maturity Level:** {summary.get('maturity_level', 'N/A')}
- **Critical Findings:** {summary.get('critical_findings_count', 0)}
- **High Findings:** {summary.get('high_findings_count', 0)}
- **Medium Findings:** {summary.get('medium_findings_count', 0)}
- **Low Findings:** {summary.get('low_findings_count', 0)}

{summary.get('summary', '')}

## Pillar Assessments

"""
    
    if "pillar_assessments" in results:
        for pillar_key, assessment in results["pillar_assessments"].items():
            if pillar_key in WAF_PILLARS:
                pillar = WAF_PILLARS[pillar_key]
                report += f"""### {pillar['icon']} {pillar['name']}

**Score:** {assessment.get('score', 'N/A')}/100

#### Findings

"""
                for finding in assessment.get("findings", []):
                    report += f"""**[{finding.get('risk_level', 'INFO')}] {finding.get('title', 'Finding')}**

{finding.get('description', '')}

- **Impact:** {finding.get('impact', 'N/A')}
- **Recommendation:** {finding.get('recommendation', 'N/A')}
- **Effort:** {finding.get('effort', 'N/A')}
- **AWS Services:** {', '.join(finding.get('aws_services', []))}

---

"""
    
    return report


def main():
    """Main application entry point"""
    init_session_state()
    render_header()
    selected_pillars, analysis_depth = render_sidebar()
    
    # Get client for later use
    client = get_anthropic_client()
    
    # Build tab list dynamically based on available modules
    tab_names = []
    
    # AWS Connector is first if available
    if AWS_CONNECTOR_AVAILABLE:
        tab_names.append("🔌 AWS Connector")
    
    # One-Touch Landscape Scanner
    if LANDSCAPE_SCANNER_AVAILABLE:
        tab_names.append("🎯 One-Touch Scan")
    
    # WAR Scanner for multi-account analysis
    if WAR_SCANNER_AVAILABLE:
        tab_names.append("🔍 Multi-Account WAR")
    
    # Standard WAF review tabs
    tab_names.extend([
        "📤 Architecture Review",
        "📊 WAF Results"
    ])
    
    if MODERNIZATION_AVAILABLE:
        tab_names.append("🚀 EKS & CI/CD")
    if FINOPS_AVAILABLE:
        tab_names.append("💰 FinOps")
    if COMPLIANCE_AVAILABLE:
        tab_names.append("📋 Compliance")
    if MIGRATION_DR_AVAILABLE:
        tab_names.append("🔄 Migration & DR")
    
    tab_names.append("📚 Knowledge Base")
    
    # Create tabs
    all_tabs = st.tabs(tab_names)
    tab_idx = 0
    
    # Tab: AWS Connector (if available)
    if AWS_CONNECTOR_AVAILABLE:
        with all_tabs[tab_idx]:
            render_aws_connector_module()
        tab_idx += 1
    
    # Tab: One-Touch Landscape Scanner (if available)
    if LANDSCAPE_SCANNER_AVAILABLE:
        with all_tabs[tab_idx]:
            render_one_touch_scanner()
        tab_idx += 1
    
    # Tab: Multi-Account WAR Scanner (if available)
    if WAR_SCANNER_AVAILABLE:
        with all_tabs[tab_idx]:
            render_multi_account_war_scanner(client)
        tab_idx += 1
    
    # Tab: Architecture Review (manual upload)
    with all_tabs[tab_idx]:
        st.markdown("### Upload Your AWS Architecture")
        st.markdown("Provide your architecture for analysis using one of the following methods:")
        
        input_method = st.radio(
            "Input Method",
            ["Architecture Diagram (Image)", "CloudFormation/Terraform (Code)", 
             "Architecture Description (Text)", "AWS Config Export (JSON)"],
            horizontal=True
        )
        
        content = None
        content_type = None
        
        if input_method == "Architecture Diagram (Image)":
            uploaded_file = st.file_uploader(
                "Upload architecture diagram",
                type=["png", "jpg", "jpeg", "gif", "webp"],
                help="Upload a clear architecture diagram showing your AWS infrastructure"
            )
            if uploaded_file:
                st.image(uploaded_file, caption="Uploaded Architecture Diagram", use_container_width=True)
                content = encode_image(uploaded_file)
                content_type = "image"
        
        elif input_method == "CloudFormation/Terraform (Code)":
            code_input = st.text_area(
                "Paste your CloudFormation template or Terraform configuration",
                height=300,
                placeholder="Paste your IaC code here..."
            )
            if code_input:
                content = code_input
                content_type = "code"
        
        elif input_method == "Architecture Description (Text)":
            text_input = st.text_area(
                "Describe your AWS architecture",
                height=300,
                placeholder="""Example:
Our application runs on AWS with the following components:
- Frontend: React app hosted on S3 with CloudFront distribution
- Backend: ECS Fargate containers running Node.js APIs
- Database: RDS PostgreSQL Multi-AZ deployment
- Cache: ElastiCache Redis cluster
- Storage: S3 buckets for user uploads
- Monitoring: CloudWatch with basic dashboards
- Security: WAF on CloudFront, Security Groups for VPC isolation
"""
            )
            if text_input:
                content = text_input
                content_type = "text"
        
        else:  # AWS Config Export
            json_input = st.text_area(
                "Paste your AWS Config export or resource inventory JSON",
                height=300,
                placeholder='{"resources": [...]}'
            )
            if json_input:
                try:
                    json.loads(json_input)  # Validate JSON
                    content = json_input
                    content_type = "json"
                except json.JSONDecodeError:
                    st.error("Invalid JSON format. Please check your input.")
        
        # Additional context
        additional_context = st.text_area(
            "Additional Context (Optional)",
            placeholder="Provide any additional context about your architecture, such as compliance requirements, expected traffic, or specific concerns...",
            height=100
        )
        
        # Analysis button
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            analyze_btn = st.button(
                "🔍 Analyze Architecture",
                type="primary",
                use_container_width=True,
                disabled=not (content and st.session_state.api_key_valid)
            )
        
        if analyze_btn and content:
            client = get_anthropic_client()
            if client:
                with st.spinner("🔄 Analyzing your architecture with Claude AI..."):
                    results = analyze_architecture(client, content, content_type, additional_context)
                    
                    if "error" not in results:
                        st.session_state.analysis_results = results
                        st.session_state.analysis_history.append({
                            "timestamp": datetime.now().isoformat(),
                            "results": results
                        })
                        st.success("✅ Analysis complete! View results in the 'Analysis Results' tab.")
                    else:
                        st.error(f"Analysis failed: {results.get('error', 'Unknown error')}")
    
    tab_idx += 1
    
    # Tab: WAF Results
    with all_tabs[tab_idx]:
        if st.session_state.analysis_results:
            results = st.session_state.analysis_results
            
            # Executive Summary
            if "executive_summary" in results:
                summary = results["executive_summary"]
                st.markdown("### 📋 Executive Summary")
                st.info(summary.get("summary", ""))
                st.markdown(f"**Maturity Level:** `{summary.get('maturity_level', 'N/A')}`")
            
            # Metrics Dashboard
            render_metrics_dashboard(results)
            
            st.markdown("---")
            
            # Detailed Results
            render_pillar_results(results)
            
            st.markdown("---")
            
            # Additional Analysis Sections
            col1, col2 = st.columns(2)
            
            with col1:
                render_roadmap(results)
                render_compliance_section(results)
            
            with col2:
                render_patterns_analysis(results)
                render_cost_analysis(results)
            
            # Export Options
            st.markdown("---")
            st.markdown("### 📥 Export Results")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                json_export = export_results(results)
                st.download_button(
                    "📄 Download JSON",
                    json_export,
                    file_name=f"waf_review_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
            
            with col2:
                md_export = generate_markdown_report(results)
                st.download_button(
                    "📝 Download Markdown Report",
                    md_export,
                    file_name=f"waf_review_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                    mime="text/markdown"
                )
            
            with col3:
                if st.button("🔄 New Analysis"):
                    st.session_state.analysis_results = None
                    st.rerun()
        else:
            st.info("👆 Upload your architecture in the 'Architecture Review' tab to begin analysis.")
    
    # Continue with enterprise module tabs
    tab_idx += 1
    
    # Tab: EKS & CI/CD (if available)
    if MODERNIZATION_AVAILABLE:
        with all_tabs[tab_idx]:
            render_modernization_planner(client)
        tab_idx += 1
    
    # Tab: FinOps (if available)
    if FINOPS_AVAILABLE:
        with all_tabs[tab_idx]:
            render_finops_module(client)
        tab_idx += 1
    
    # Tab: Compliance (if available)
    if COMPLIANCE_AVAILABLE:
        with all_tabs[tab_idx]:
            render_compliance_module(client)
        tab_idx += 1
    
    # Tab: Migration & DR (if available)
    if MIGRATION_DR_AVAILABLE:
        with all_tabs[tab_idx]:
            render_migration_dr_module(client)
        tab_idx += 1
    
    # Tab: Knowledge Base (always last)
    with all_tabs[-1]:
        st.markdown("### 📚 AWS Well-Architected Framework Knowledge Base")
        
        st.markdown("""
        The AWS Well-Architected Framework helps you understand the pros and cons of decisions 
        you make while building systems on AWS. Using the Framework helps you learn architectural 
        best practices for designing and operating reliable, secure, efficient, cost-effective, 
        and sustainable systems in the cloud.
        """)
        
        # Pillar Details
        for pillar_key, pillar in WAF_PILLARS.items():
            with st.expander(f"{pillar['icon']} {pillar['name']}"):
                st.markdown(f"**{pillar['description']}**")
                st.markdown("**Focus Areas:**")
                for area in pillar['focus_areas']:
                    st.markdown(f"- {area}")
                
                st.markdown(f"""
                <a href="https://docs.aws.amazon.com/wellarchitected/latest/framework/{pillar_key.replace('_', '-')}.html" 
                   target="_blank" style="color: #FF9900;">
                   📖 Learn more in AWS Documentation →
                </a>
                """, unsafe_allow_html=True)
        
        # Quick Reference
        st.markdown("### 🎯 Risk Level Reference")
        
        for level, info in RISK_LEVELS.items():
            st.markdown(f"""
            <div style="display: flex; align-items: center; margin: 0.5rem 0;">
                <span class="risk-badge risk-{level.lower()}">{level}</span>
                <span style="margin-left: 1rem;">{info['description']}</span>
            </div>
            """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
