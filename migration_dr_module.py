"""
Enterprise Migration Assessment & Disaster Recovery Planning Module
Cloud migration readiness assessment and business continuity planning

Features:
- Migration Readiness Assessment (MRA)
- Application Portfolio Analysis
- 6R Migration Strategy Recommendations
- TCO Comparison & ROI Calculator
- Dependency Mapping
- Disaster Recovery Planning
- RTO/RPO Analysis
- Business Impact Analysis
- DR Architecture Patterns
- Failover Testing Plans
"""

import streamlit as st
import anthropic
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# ============================================================================
# MIGRATION STRATEGIES (6Rs + 1)
# ============================================================================

MIGRATION_STRATEGIES = {
    "rehost": {
        "name": "Rehost (Lift & Shift)",
        "icon": "🏗️",
        "description": "Move applications without changes to cloud infrastructure",
        "complexity": "Low",
        "time": "1-3 months",
        "cost_reduction": "10-20%",
        "best_for": ["Legacy applications", "Quick migrations", "Compliance requirements"],
        "aws_services": ["EC2", "EBS", "VPC", "Application Migration Service"],
        "considerations": ["May not leverage cloud-native benefits", "Same operational model"]
    },
    "replatform": {
        "name": "Replatform (Lift & Reshape)",
        "icon": "🔧",
        "description": "Make targeted optimizations during migration",
        "complexity": "Medium",
        "time": "2-6 months",
        "cost_reduction": "20-40%",
        "best_for": ["Database migrations", "OS upgrades", "Managed services adoption"],
        "aws_services": ["RDS", "ElastiCache", "Elastic Beanstalk", "ECS"],
        "considerations": ["Balance between speed and optimization", "Some refactoring required"]
    },
    "repurchase": {
        "name": "Repurchase (Drop & Shop)",
        "icon": "🛒",
        "description": "Replace with SaaS or cloud-native alternative",
        "complexity": "Medium",
        "time": "1-4 months",
        "cost_reduction": "Variable",
        "best_for": ["CRM", "HR systems", "Email", "Collaboration tools"],
        "aws_services": ["AWS Marketplace", "SaaS integrations"],
        "considerations": ["Data migration complexity", "Change management", "Licensing costs"]
    },
    "refactor": {
        "name": "Refactor (Re-architect)",
        "icon": "🏛️",
        "description": "Re-architect using cloud-native services",
        "complexity": "High",
        "time": "6-18 months",
        "cost_reduction": "40-70%",
        "best_for": ["Core business applications", "High-growth systems", "Scalability needs"],
        "aws_services": ["Lambda", "EKS", "DynamoDB", "API Gateway", "Step Functions"],
        "considerations": ["Highest effort", "Requires skilled team", "Maximum cloud benefits"]
    },
    "retain": {
        "name": "Retain (Revisit Later)",
        "icon": "⏸️",
        "description": "Keep on-premises for now, migrate later",
        "complexity": "N/A",
        "time": "N/A",
        "cost_reduction": "0%",
        "best_for": ["Recent investments", "Complex dependencies", "Compliance restrictions"],
        "aws_services": ["Direct Connect", "Outposts", "Hybrid solutions"],
        "considerations": ["Technical debt", "May become more complex over time"]
    },
    "retire": {
        "name": "Retire (Decommission)",
        "icon": "🗑️",
        "description": "Identify and remove unnecessary applications",
        "complexity": "Low",
        "time": "1-2 months",
        "cost_reduction": "100%",
        "best_for": ["Redundant systems", "Unused applications", "End-of-life software"],
        "aws_services": [],
        "considerations": ["Data archival requirements", "Dependencies on other systems"]
    },
    "relocate": {
        "name": "Relocate (Hypervisor-level)",
        "icon": "📦",
        "description": "Move VMware workloads to VMware Cloud on AWS",
        "complexity": "Low",
        "time": "1-3 months",
        "cost_reduction": "10-30%",
        "best_for": ["VMware environments", "Quick cloud entry", "Maintain existing tools"],
        "aws_services": ["VMware Cloud on AWS"],
        "considerations": ["VMware licensing", "Specific use case"]
    }
}

# Disaster Recovery Patterns
DR_PATTERNS = {
    "backup_restore": {
        "name": "Backup & Restore",
        "icon": "💾",
        "rpo": "Hours",
        "rto": "Hours to Days",
        "cost": "Lowest",
        "description": "Regular backups with restoration on demand",
        "aws_services": ["S3", "Glacier", "AWS Backup", "EBS Snapshots"],
        "best_for": ["Non-critical systems", "Cost-sensitive", "Dev/Test"],
        "monthly_cost_estimate": "$50-500"
    },
    "pilot_light": {
        "name": "Pilot Light",
        "icon": "🔥",
        "rpo": "Minutes",
        "rto": "Hours",
        "cost": "Low",
        "description": "Minimal version always running, scale up during disaster",
        "aws_services": ["RDS Multi-AZ", "EC2", "Route 53", "Auto Scaling"],
        "best_for": ["Important applications", "Moderate recovery needs"],
        "monthly_cost_estimate": "$500-2,000"
    },
    "warm_standby": {
        "name": "Warm Standby",
        "icon": "🌡️",
        "rpo": "Seconds to Minutes",
        "rto": "Minutes to Hours",
        "cost": "Medium",
        "description": "Scaled-down but fully functional copy in DR region",
        "aws_services": ["RDS Read Replicas", "EC2", "ALB", "Route 53", "Aurora Global"],
        "best_for": ["Business-critical applications", "Faster recovery required"],
        "monthly_cost_estimate": "$2,000-10,000"
    },
    "multi_site": {
        "name": "Multi-Site Active/Active",
        "icon": "🌐",
        "rpo": "Near Zero",
        "rto": "Near Zero",
        "cost": "Highest",
        "description": "Full production capacity in multiple regions",
        "aws_services": ["Global Accelerator", "Route 53", "DynamoDB Global Tables", "Aurora Global", "S3 Cross-Region"],
        "best_for": ["Mission-critical", "Zero downtime requirements", "Global users"],
        "monthly_cost_estimate": "$10,000-50,000+"
    }
}

# Business Impact Levels
BIA_LEVELS = {
    "critical": {
        "name": "Critical",
        "max_downtime": "< 1 hour",
        "data_loss_tolerance": "< 1 minute",
        "financial_impact": "Severe",
        "recommended_dr": "multi_site",
        "rpo_target": "Near Zero",
        "rto_target": "< 15 minutes"
    },
    "high": {
        "name": "High",
        "max_downtime": "< 4 hours",
        "data_loss_tolerance": "< 15 minutes",
        "financial_impact": "Significant",
        "recommended_dr": "warm_standby",
        "rpo_target": "< 15 minutes",
        "rto_target": "< 1 hour"
    },
    "medium": {
        "name": "Medium",
        "max_downtime": "< 24 hours",
        "data_loss_tolerance": "< 1 hour",
        "financial_impact": "Moderate",
        "recommended_dr": "pilot_light",
        "rpo_target": "< 1 hour",
        "rto_target": "< 4 hours"
    },
    "low": {
        "name": "Low",
        "max_downtime": "< 72 hours",
        "data_loss_tolerance": "< 24 hours",
        "financial_impact": "Minor",
        "recommended_dr": "backup_restore",
        "rpo_target": "< 24 hours",
        "rto_target": "< 24 hours"
    }
}


def build_migration_analysis_prompt(portfolio_data: Dict) -> str:
    """Build the migration analysis prompt"""
    
    strategies_detail = "\n".join([
        f"- **{s['name']}**: {s['description']} (Complexity: {s['complexity']}, Time: {s['time']})"
        for s in MIGRATION_STRATEGIES.values()
    ])
    
    prompt = f"""You are an expert AWS Migration specialist with deep experience in enterprise cloud migrations.

Analyze the following application portfolio and provide migration recommendations.

## Application Portfolio:
{json.dumps(portfolio_data, indent=2)}

## Available Migration Strategies (6Rs):
{strategies_detail}

## Provide your analysis in the following JSON structure:

```json
{{
    "migration_summary": {{
        "total_applications": <number>,
        "migration_readiness_score": <0-100>,
        "estimated_timeline_months": <number>,
        "total_tco_savings_percentage": <number>,
        "executive_summary": "<summary>"
    }},
    "application_assessments": [
        {{
            "application_name": "<name>",
            "current_state": {{
                "environment": "<on-prem|hybrid|cloud>",
                "technology_stack": ["<tech1>", "<tech2>"],
                "dependencies": ["<dep1>", "<dep2>"],
                "monthly_cost": <number>,
                "criticality": "<critical|high|medium|low>"
            }},
            "recommended_strategy": "<rehost|replatform|repurchase|refactor|retain|retire|relocate>",
            "strategy_rationale": "<why this strategy>",
            "migration_complexity": "<low|medium|high>",
            "estimated_effort_weeks": <number>,
            "target_architecture": {{
                "aws_services": ["<service1>", "<service2>"],
                "architecture_pattern": "<pattern>",
                "high_availability": <true|false>,
                "disaster_recovery": "<backup_restore|pilot_light|warm_standby|multi_site>"
            }},
            "cost_analysis": {{
                "current_monthly_cost": <number>,
                "projected_monthly_cost": <number>,
                "migration_cost": <number>,
                "monthly_savings": <number>,
                "roi_months": <number>
            }},
            "risks": [
                {{
                    "risk": "<risk description>",
                    "impact": "<high|medium|low>",
                    "mitigation": "<mitigation strategy>"
                }}
            ],
            "dependencies_to_resolve": ["<dependency1>", "<dependency2>"],
            "migration_wave": <1-5>
        }}
    ],
    "migration_waves": [
        {{
            "wave": <number>,
            "name": "<wave name>",
            "applications": ["<app1>", "<app2>"],
            "duration_weeks": <number>,
            "key_milestones": ["<milestone1>", "<milestone2>"],
            "resources_required": {{
                "architects": <number>,
                "engineers": <number>,
                "testers": <number>
            }},
            "success_criteria": ["<criteria1>", "<criteria2>"]
        }}
    ],
    "tco_comparison": {{
        "current_annual_cost": <number>,
        "projected_annual_cost": <number>,
        "migration_investment": <number>,
        "annual_savings": <number>,
        "3_year_savings": <number>,
        "payback_period_months": <number>,
        "roi_percentage": <number>
    }},
    "risk_assessment": {{
        "overall_risk_level": "<high|medium|low>",
        "top_risks": [
            {{
                "risk": "<risk>",
                "category": "<technical|organizational|financial>",
                "probability": "<high|medium|low>",
                "impact": "<high|medium|low>",
                "mitigation": "<mitigation>"
            }}
        ]
    }},
    "recommendations": [
        {{
            "priority": <1-5>,
            "recommendation": "<recommendation>",
            "rationale": "<why>",
            "effort": "<low|medium|high>",
            "impact": "<high|medium|low>"
        }}
    ]
}}
```

Provide specific, actionable recommendations with realistic timelines and cost estimates.
"""
    return prompt


def build_dr_analysis_prompt(environment_data: Dict) -> str:
    """Build the DR analysis prompt"""
    
    prompt = f"""You are an expert AWS Solutions Architect specializing in disaster recovery and business continuity.

Analyze the following environment and provide comprehensive DR recommendations.

## Environment Data:
{json.dumps(environment_data, indent=2)}

## Available DR Patterns:
- Backup & Restore: RPO Hours, RTO Hours-Days, Lowest cost
- Pilot Light: RPO Minutes, RTO Hours, Low cost
- Warm Standby: RPO Seconds-Minutes, RTO Minutes-Hours, Medium cost
- Multi-Site Active/Active: RPO Near Zero, RTO Near Zero, Highest cost

## Provide your analysis in the following JSON structure:

```json
{{
    "dr_summary": {{
        "current_dr_maturity": "<None|Basic|Intermediate|Advanced>",
        "recommended_pattern": "<backup_restore|pilot_light|warm_standby|multi_site>",
        "estimated_monthly_cost": <number>,
        "implementation_weeks": <number>,
        "executive_summary": "<summary>"
    }},
    "business_impact_analysis": [
        {{
            "system": "<system name>",
            "criticality": "<critical|high|medium|low>",
            "max_tolerable_downtime": "<time>",
            "data_loss_tolerance": "<time>",
            "financial_impact_per_hour": <number>,
            "recommended_rpo": "<time>",
            "recommended_rto": "<time>",
            "recommended_dr_pattern": "<pattern>"
        }}
    ],
    "dr_architecture": {{
        "primary_region": "<region>",
        "dr_region": "<region>",
        "components": [
            {{
                "component": "<name>",
                "primary_service": "<service>",
                "dr_service": "<service>",
                "replication_method": "<method>",
                "failover_mechanism": "<mechanism>"
            }}
        ],
        "network_design": {{
            "cross_region_connectivity": "<method>",
            "dns_failover": "<Route53 health checks|Global Accelerator>",
            "estimated_failover_time": "<time>"
        }}
    }},
    "implementation_plan": [
        {{
            "phase": <number>,
            "name": "<phase name>",
            "duration_weeks": <number>,
            "tasks": ["<task1>", "<task2>"],
            "deliverables": ["<deliverable1>"],
            "dependencies": ["<dependency1>"]
        }}
    ],
    "testing_plan": {{
        "test_frequency": "<frequency>",
        "test_types": [
            {{
                "test": "<test name>",
                "description": "<description>",
                "frequency": "<frequency>",
                "duration": "<duration>",
                "impact": "<production impact>"
            }}
        ],
        "success_criteria": ["<criteria1>", "<criteria2>"]
    }},
    "cost_breakdown": {{
        "infrastructure_monthly": <number>,
        "data_transfer_monthly": <number>,
        "storage_monthly": <number>,
        "total_monthly": <number>,
        "implementation_one_time": <number>
    }},
    "runbook_outline": [
        {{
            "scenario": "<scenario>",
            "trigger": "<trigger condition>",
            "steps": ["<step1>", "<step2>"],
            "rollback_steps": ["<rollback1>"],
            "contacts": ["<contact1>"]
        }}
    ]
}}
```

Provide specific AWS service configurations and realistic cost estimates.
"""
    return prompt


def analyze_migration_with_ai(client: anthropic.Anthropic, portfolio_data: Dict) -> Dict:
    """Analyze migration using Claude AI"""
    
    prompt = build_migration_analysis_prompt(portfolio_data)
    
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=8000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        response_text = response.content[0].text
        
        import re
        json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(1))
        return json.loads(response_text)
        
    except Exception as e:
        return {"error": str(e)}


def analyze_dr_with_ai(client: anthropic.Anthropic, environment_data: Dict) -> Dict:
    """Analyze DR requirements using Claude AI"""
    
    prompt = build_dr_analysis_prompt(environment_data)
    
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=8000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        response_text = response.content[0].text
        
        import re
        json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(1))
        return json.loads(response_text)
        
    except Exception as e:
        return {"error": str(e)}


def render_migration_results(results: Dict):
    """Render migration assessment results"""
    
    if "error" in results:
        st.error(f"Analysis failed: {results['error']}")
        return
    
    summary = results.get('migration_summary', {})
    
    st.markdown("### 📊 Migration Assessment Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Applications", summary.get('total_applications', 0))
    with col2:
        st.metric("Readiness Score", f"{summary.get('migration_readiness_score', 0)}%")
    with col3:
        st.metric("Timeline", f"{summary.get('estimated_timeline_months', 0)} months")
    with col4:
        st.metric("TCO Savings", f"{summary.get('total_tco_savings_percentage', 0)}%")
    
    st.info(summary.get('executive_summary', ''))
    
    # Application Assessments
    if results.get('application_assessments'):
        st.markdown("### 📱 Application Recommendations")
        
        for app in results['application_assessments']:
            strategy = app.get('recommended_strategy', 'unknown')
            strategy_info = MIGRATION_STRATEGIES.get(strategy, {})
            
            with st.expander(f"{strategy_info.get('icon', '📦')} {app.get('application_name', 'App')} → {strategy_info.get('name', strategy)}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Current Cost:** ${app.get('cost_analysis', {}).get('current_monthly_cost', 0):,}/mo")
                    st.markdown(f"**Projected Cost:** ${app.get('cost_analysis', {}).get('projected_monthly_cost', 0):,}/mo")
                    st.markdown(f"**Monthly Savings:** ${app.get('cost_analysis', {}).get('monthly_savings', 0):,}")
                    st.markdown(f"**Migration Wave:** {app.get('migration_wave', 'TBD')}")
                
                with col2:
                    st.markdown(f"**Complexity:** {app.get('migration_complexity', 'N/A')}")
                    st.markdown(f"**Effort:** {app.get('estimated_effort_weeks', 0)} weeks")
                    st.markdown(f"**ROI:** {app.get('cost_analysis', {}).get('roi_months', 0)} months")
                
                st.markdown(f"**Rationale:** {app.get('strategy_rationale', 'N/A')}")
                
                if app.get('target_architecture', {}).get('aws_services'):
                    st.markdown(f"**AWS Services:** {', '.join(app['target_architecture']['aws_services'])}")


def render_dr_results(results: Dict):
    """Render DR planning results"""
    
    if "error" in results:
        st.error(f"Analysis failed: {results['error']}")
        return
    
    summary = results.get('dr_summary', {})
    
    st.markdown("### 🛡️ Disaster Recovery Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Current Maturity", summary.get('current_dr_maturity', 'Unknown'))
    with col2:
        pattern = summary.get('recommended_pattern', 'unknown')
        pattern_info = DR_PATTERNS.get(pattern, {})
        st.metric("Recommended Pattern", pattern_info.get('name', pattern))
    with col3:
        st.metric("Monthly Cost", f"${summary.get('estimated_monthly_cost', 0):,}")
    with col4:
        st.metric("Implementation", f"{summary.get('implementation_weeks', 0)} weeks")
    
    st.info(summary.get('executive_summary', ''))


def render_migration_dr_module(client: Optional[anthropic.Anthropic]):
    """Main renderer for Migration & DR module"""
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #7B1FA2 0%, #9C27B0 100%); padding: 1.5rem; border-radius: 12px; margin-bottom: 1.5rem;">
        <h2 style="color: white; margin: 0;">🚀 Migration Assessment & Disaster Recovery</h2>
        <p style="color: #E1BEE7; margin: 0.5rem 0 0 0;">Cloud Migration Strategy & Business Continuity Planning</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize session state
    if "migration_results" not in st.session_state:
        st.session_state.migration_results = None
    if "dr_results" not in st.session_state:
        st.session_state.dr_results = None
    
    # Create tabs
    tabs = st.tabs([
        "📊 Migration Assessment",
        "🎯 Strategy Reference",
        "🛡️ DR Planning",
        "📋 DR Patterns"
    ])
    
    # Tab 1: Migration Assessment
    with tabs[0]:
        st.markdown("### 📱 Application Portfolio Assessment")
        
        # Add applications
        num_apps = st.number_input("Number of Applications", min_value=1, max_value=20, value=3)
        
        applications = []
        for i in range(int(num_apps)):
            with st.expander(f"Application {i+1}", expanded=(i == 0)):
                col1, col2 = st.columns(2)
                
                with col1:
                    name = st.text_input(f"Name", value=f"App-{i+1}", key=f"app_name_{i}")
                    env = st.selectbox(f"Environment", ["On-Premises", "Hybrid", "Cloud"], key=f"app_env_{i}")
                    tech = st.multiselect(f"Technology Stack", 
                        [".NET", "Java", "Python", "Node.js", "PHP", "Legacy COBOL", "Oracle", "SQL Server"],
                        key=f"app_tech_{i}")
                
                with col2:
                    cost = st.number_input(f"Monthly Cost ($)", value=5000, key=f"app_cost_{i}")
                    criticality = st.selectbox(f"Criticality", ["Critical", "High", "Medium", "Low"], key=f"app_crit_{i}")
                    users = st.number_input(f"User Count", value=100, key=f"app_users_{i}")
                
                applications.append({
                    "name": name,
                    "environment": env,
                    "technology_stack": tech,
                    "monthly_cost": cost,
                    "criticality": criticality.lower(),
                    "user_count": users
                })
        
        portfolio_data = {
            "applications": applications,
            "organization": {
                "industry": st.selectbox("Industry", ["Technology", "Finance", "Healthcare", "Retail", "Manufacturing"]),
                "cloud_experience": st.selectbox("Cloud Experience", ["None", "Limited", "Moderate", "Advanced"]),
                "timeline_preference": st.selectbox("Timeline", ["Aggressive (6-12 months)", "Standard (12-18 months)", "Conservative (18-24 months)"])
            }
        }
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("🔍 Analyze Migration", type="primary", use_container_width=True, disabled=not client):
                with st.spinner("Analyzing portfolio..."):
                    results = analyze_migration_with_ai(client, portfolio_data)
                    if "error" not in results:
                        st.session_state.migration_results = results
                        st.success("✅ Analysis complete!")
                    else:
                        st.error(f"Analysis failed: {results['error']}")
        
        if st.session_state.migration_results:
            render_migration_results(st.session_state.migration_results)
    
    # Tab 2: Strategy Reference
    with tabs[1]:
        st.markdown("### 📚 Migration Strategy Reference (6Rs)")
        
        for strategy_id, strategy in MIGRATION_STRATEGIES.items():
            with st.expander(f"{strategy['icon']} {strategy['name']}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Description:** {strategy['description']}")
                    st.markdown(f"**Complexity:** {strategy['complexity']}")
                    st.markdown(f"**Timeline:** {strategy['time']}")
                    st.markdown(f"**Cost Reduction:** {strategy['cost_reduction']}")
                
                with col2:
                    st.markdown("**Best For:**")
                    for item in strategy['best_for']:
                        st.markdown(f"- {item}")
                    
                    if strategy['aws_services']:
                        st.markdown(f"**AWS Services:** {', '.join(strategy['aws_services'])}")
    
    # Tab 3: DR Planning
    with tabs[2]:
        st.markdown("### 🛡️ Disaster Recovery Planning")
        
        col1, col2 = st.columns(2)
        
        with col1:
            primary_region = st.selectbox("Primary Region", ["us-east-1", "us-west-2", "eu-west-1"])
            workload_type = st.selectbox("Workload Type", ["Web Application", "Database", "Microservices", "Batch Processing"])
            current_dr = st.selectbox("Current DR Status", ["None", "Basic Backups", "Manual Procedures", "Automated"])
        
        with col2:
            rto_requirement = st.selectbox("RTO Requirement", ["< 1 hour", "< 4 hours", "< 24 hours", "< 72 hours"])
            rpo_requirement = st.selectbox("RPO Requirement", ["Near Zero", "< 15 minutes", "< 1 hour", "< 24 hours"])
            budget = st.selectbox("Monthly DR Budget", ["< $1,000", "$1,000-5,000", "$5,000-20,000", "> $20,000"])
        
        environment_data = {
            "primary_region": primary_region,
            "workload_type": workload_type,
            "current_dr_status": current_dr,
            "rto_requirement": rto_requirement,
            "rpo_requirement": rpo_requirement,
            "monthly_budget": budget
        }
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("🔍 Generate DR Plan", type="primary", use_container_width=True, disabled=not client):
                with st.spinner("Planning DR architecture..."):
                    results = analyze_dr_with_ai(client, environment_data)
                    if "error" not in results:
                        st.session_state.dr_results = results
                        st.success("✅ DR Plan generated!")
                    else:
                        st.error(f"Planning failed: {results['error']}")
        
        if st.session_state.dr_results:
            render_dr_results(st.session_state.dr_results)
    
    # Tab 4: DR Patterns
    with tabs[3]:
        st.markdown("### 📚 Disaster Recovery Pattern Reference")
        
        for pattern_id, pattern in DR_PATTERNS.items():
            with st.expander(f"{pattern['icon']} {pattern['name']} (RTO: {pattern['rto']}, RPO: {pattern['rpo']})"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Description:** {pattern['description']}")
                    st.markdown(f"**Cost Level:** {pattern['cost']}")
                    st.markdown(f"**Estimated Monthly:** {pattern['monthly_cost_estimate']}")
                
                with col2:
                    st.markdown("**Best For:**")
                    for item in pattern['best_for']:
                        st.markdown(f"- {item}")
                    
                    st.markdown(f"**AWS Services:** {', '.join(pattern['aws_services'])}")


# Export
__all__ = ['render_migration_dr_module', 'MIGRATION_STRATEGIES', 'DR_PATTERNS', 'BIA_LEVELS']
