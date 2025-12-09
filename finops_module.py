"""
Enterprise FinOps Module - AI-Powered Cost Management
Complete FinOps platform with cost intelligence, anomaly detection, and sustainability tracking

Features:
- AI-Powered Cost Analysis & Predictions
- Cost Anomaly Detection with Auto-Alerting
- Right-Sizing Recommendations
- Reserved Instance & Savings Plans Analysis
- Budget Management & Forecasting
- Tag-Based Cost Allocation
- Sustainability & Carbon Footprint Tracking
- Multi-Account Cost Consolidation
- Showback/Chargeback Reports
- FinOps Maturity Assessment
"""

import streamlit as st
import anthropic
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import random

# ============================================================================
# FINOPS MATURITY MODEL
# ============================================================================

FINOPS_MATURITY_MODEL = {
    "crawl": {
        "name": "Crawl",
        "description": "Basic visibility and allocation",
        "characteristics": [
            "Basic cost reporting in place",
            "Limited tagging strategy",
            "Reactive cost management",
            "No forecasting capabilities",
            "Limited stakeholder awareness"
        ],
        "target_capabilities": [
            "Implement comprehensive tagging",
            "Set up basic budgets and alerts",
            "Establish cost visibility dashboards",
            "Identify quick-win optimizations"
        ],
        "score_range": [0, 33]
    },
    "walk": {
        "name": "Walk",
        "description": "Proactive optimization and accountability",
        "characteristics": [
            "Comprehensive cost allocation",
            "Regular optimization reviews",
            "Basic forecasting capabilities",
            "Team cost awareness",
            "Reserved Instance coverage"
        ],
        "target_capabilities": [
            "Implement automated rightsizing",
            "Establish showback/chargeback",
            "Advanced forecasting models",
            "Anomaly detection automation"
        ],
        "score_range": [34, 66]
    },
    "run": {
        "name": "Run",
        "description": "Automated optimization and continuous improvement",
        "characteristics": [
            "AI-driven cost optimization",
            "Real-time anomaly detection",
            "Automated remediation",
            "Accurate forecasting",
            "Full cost accountability"
        ],
        "target_capabilities": [
            "Predictive cost modeling",
            "Sustainability optimization",
            "Zero-waste initiatives",
            "Industry benchmarking"
        ],
        "score_range": [67, 100]
    }
}

# Cost Categories
COST_CATEGORIES = {
    "compute": {
        "name": "Compute",
        "icon": "🖥️",
        "services": ["EC2", "Lambda", "ECS", "EKS", "Fargate", "Batch"],
        "optimization_strategies": [
            "Right-sizing instances",
            "Reserved Instances",
            "Spot Instances",
            "Savings Plans",
            "Auto-scaling optimization"
        ]
    },
    "storage": {
        "name": "Storage",
        "icon": "💾",
        "services": ["S3", "EBS", "EFS", "FSx", "Glacier"],
        "optimization_strategies": [
            "Lifecycle policies",
            "Storage class optimization",
            "Delete unused volumes",
            "Intelligent tiering",
            "Compression/deduplication"
        ]
    },
    "database": {
        "name": "Database",
        "icon": "🗄️",
        "services": ["RDS", "DynamoDB", "ElastiCache", "Redshift", "Aurora"],
        "optimization_strategies": [
            "Reserved instances",
            "Right-sizing",
            "Aurora Serverless",
            "DynamoDB on-demand",
            "Read replica optimization"
        ]
    },
    "networking": {
        "name": "Networking",
        "icon": "🌐",
        "services": ["Data Transfer", "CloudFront", "Route53", "VPC", "Direct Connect"],
        "optimization_strategies": [
            "VPC endpoints",
            "CloudFront optimization",
            "Data transfer reduction",
            "Regional placement",
            "NAT Gateway optimization"
        ]
    },
    "analytics": {
        "name": "Analytics",
        "icon": "📊",
        "services": ["Athena", "EMR", "Glue", "Kinesis", "OpenSearch"],
        "optimization_strategies": [
            "Query optimization",
            "Data partitioning",
            "Spot instances for EMR",
            "Reserved capacity",
            "Data compression"
        ]
    }
}

# Sustainability Metrics
SUSTAINABILITY_CONFIG = {
    "regions": {
        "us-west-2": {"carbon_intensity": 0.25, "renewable_percentage": 85},
        "eu-west-1": {"carbon_intensity": 0.35, "renewable_percentage": 70},
        "us-east-1": {"carbon_intensity": 0.45, "renewable_percentage": 55},
        "ap-southeast-1": {"carbon_intensity": 0.60, "renewable_percentage": 40},
        "ap-south-1": {"carbon_intensity": 0.75, "renewable_percentage": 25}
    },
    "instance_efficiency": {
        "graviton": 0.60,  # 40% more efficient
        "intel": 1.0,
        "amd": 0.85
    }
}


def build_finops_analysis_prompt(cost_data: Dict, query: str = "") -> str:
    """Build the AI analysis prompt for FinOps"""
    
    prompt = f"""You are an expert FinOps practitioner and AWS cost optimization specialist.
Analyze the following cost data and provide actionable insights.

## Cost Data:
{json.dumps(cost_data, indent=2)}

{"## User Query: " + query if query else ""}

## Provide your analysis in the following JSON structure:

```json
{{
    "executive_summary": {{
        "total_monthly_cost": <number>,
        "month_over_month_change": "<percentage>",
        "annual_forecast": <number>,
        "optimization_potential": "<percentage>",
        "summary": "<2-3 sentence executive summary>"
    }},
    "cost_drivers": [
        {{
            "category": "<category>",
            "service": "<service>",
            "cost": <number>,
            "percentage_of_total": <number>,
            "trend": "<increasing|stable|decreasing>",
            "insight": "<specific insight>"
        }}
    ],
    "anomalies_detected": [
        {{
            "date": "<date>",
            "service": "<service>",
            "expected_cost": <number>,
            "actual_cost": <number>,
            "deviation_percentage": <number>,
            "severity": "<critical|high|medium|low>",
            "probable_cause": "<cause>",
            "recommended_action": "<action>"
        }}
    ],
    "optimization_recommendations": [
        {{
            "category": "<category>",
            "recommendation": "<specific recommendation>",
            "current_cost": <number>,
            "projected_cost": <number>,
            "monthly_savings": <number>,
            "annual_savings": <number>,
            "effort": "<low|medium|high>",
            "risk": "<low|medium|high>",
            "implementation_steps": ["<step1>", "<step2>"],
            "aws_services_involved": ["<service1>", "<service2>"]
        }}
    ],
    "reserved_instance_analysis": {{
        "current_ri_coverage": <percentage>,
        "recommended_ri_coverage": <percentage>,
        "potential_savings": <number>,
        "recommendations": ["<recommendation1>", "<recommendation2>"]
    }},
    "sustainability_insights": {{
        "estimated_carbon_footprint_kg": <number>,
        "carbon_reduction_opportunities": ["<opportunity1>", "<opportunity2>"],
        "green_region_recommendations": ["<region1>", "<region2>"]
    }},
    "forecast": {{
        "next_month_estimate": <number>,
        "quarter_estimate": <number>,
        "confidence_level": "<high|medium|low>",
        "factors_affecting_forecast": ["<factor1>", "<factor2>"]
    }},
    "finops_maturity_assessment": {{
        "current_level": "<Crawl|Walk|Run>",
        "score": <0-100>,
        "strengths": ["<strength1>", "<strength2>"],
        "improvement_areas": ["<area1>", "<area2>"],
        "next_steps": ["<step1>", "<step2>"]
    }}
}}
```

Provide specific, actionable recommendations with real dollar amounts.
Focus on quick wins and high-impact optimizations.
"""
    return prompt


def generate_demo_cost_data() -> Dict:
    """Generate demo cost data for analysis"""
    
    # Generate 30 days of cost data
    daily_costs = []
    base_cost = 650
    for i in range(30):
        date = (datetime.now() - timedelta(days=29-i)).strftime('%Y-%m-%d')
        # Add some variation and a spike
        variation = random.uniform(-50, 80)
        spike = 300 if i == 22 else 0  # Anomaly on day 22
        daily_costs.append({
            "date": date,
            "cost": round(base_cost + variation + spike, 2)
        })
    
    return {
        "period": "Last 30 Days",
        "total_cost": 24850,
        "currency": "USD",
        "by_service": {
            "EC2": 8500,
            "RDS": 5200,
            "S3": 2100,
            "Lambda": 1800,
            "Data Transfer": 1500,
            "EKS": 2400,
            "CloudWatch": 950,
            "Other": 2400
        },
        "by_account": {
            "Production": 15200,
            "Staging": 5400,
            "Development": 3100,
            "Sandbox": 1150
        },
        "by_environment": {
            "Production": 15200,
            "Non-Production": 9650
        },
        "daily_costs": daily_costs,
        "reserved_instance_coverage": 45,
        "savings_plan_coverage": 20,
        "spot_usage_percentage": 15,
        "untagged_resources_cost": 3200,
        "idle_resources_cost": 2800
    }


def analyze_costs_with_ai(client: anthropic.Anthropic, cost_data: Dict, 
                          query: str = "") -> Dict:
    """Analyze costs using Claude AI"""
    
    prompt = build_finops_analysis_prompt(cost_data, query)
    
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=6000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        response_text = response.content[0].text
        
        # Extract JSON
        import re
        json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(1))
        else:
            return json.loads(response_text)
            
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse response: {e}"}
    except Exception as e:
        return {"error": str(e)}


def render_finops_dashboard(results: Dict):
    """Render the FinOps analysis dashboard"""
    
    if "error" in results:
        st.error(f"Analysis failed: {results['error']}")
        return
    
    # Executive Summary
    if "executive_summary" in results:
        summary = results["executive_summary"]
        
        st.markdown("### 📊 Executive Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Monthly Cost",
                f"${summary.get('total_monthly_cost', 0):,.0f}",
                delta=summary.get('month_over_month_change', 'N/A')
            )
        
        with col2:
            st.metric(
                "Annual Forecast",
                f"${summary.get('annual_forecast', 0):,.0f}"
            )
        
        with col3:
            st.metric(
                "Optimization Potential",
                summary.get('optimization_potential', 'N/A'),
                delta="savings opportunity"
            )
        
        with col4:
            maturity = results.get('finops_maturity_assessment', {})
            st.metric(
                "FinOps Maturity",
                maturity.get('current_level', 'N/A'),
                delta=f"Score: {maturity.get('score', 0)}/100"
            )
        
        st.info(summary.get('summary', ''))


def render_cost_anomalies(results: Dict):
    """Render cost anomalies section"""
    
    if "anomalies_detected" not in results:
        return
    
    anomalies = results["anomalies_detected"]
    
    st.markdown("### 🚨 Cost Anomalies Detected")
    
    if not anomalies:
        st.success("✅ No significant cost anomalies detected")
        return
    
    for anomaly in anomalies:
        severity = anomaly.get('severity', 'medium')
        severity_color = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }.get(severity, '⚪')
        
        with st.expander(f"{severity_color} {anomaly.get('service', 'Unknown')} - {anomaly.get('date', 'N/A')} (+{anomaly.get('deviation_percentage', 0):.0f}%)", expanded=(severity in ['critical', 'high'])):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown(f"**Expected Cost:** ${anomaly.get('expected_cost', 0):,.2f}")
                st.markdown(f"**Actual Cost:** ${anomaly.get('actual_cost', 0):,.2f}")
                st.markdown(f"**Deviation:** +{anomaly.get('deviation_percentage', 0):.1f}%")
            
            with col2:
                st.markdown(f"**Probable Cause:** {anomaly.get('probable_cause', 'Unknown')}")
                st.markdown(f"**Recommended Action:** {anomaly.get('recommended_action', 'Review manually')}")


def render_optimization_recommendations(results: Dict):
    """Render optimization recommendations"""
    
    if "optimization_recommendations" not in results:
        return
    
    recommendations = results["optimization_recommendations"]
    
    st.markdown("### 💡 Optimization Recommendations")
    
    # Summary metrics
    total_monthly_savings = sum(r.get('monthly_savings', 0) for r in recommendations)
    total_annual_savings = sum(r.get('annual_savings', 0) for r in recommendations)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Monthly Savings Potential", f"${total_monthly_savings:,.0f}")
    with col2:
        st.metric("Annual Savings Potential", f"${total_annual_savings:,.0f}")
    with col3:
        st.metric("Recommendations", len(recommendations))
    
    st.markdown("---")
    
    for idx, rec in enumerate(recommendations):
        effort_color = {'low': '🟢', 'medium': '🟡', 'high': '🔴'}.get(rec.get('effort', 'medium'), '⚪')
        
        with st.expander(f"💰 {rec.get('recommendation', 'Recommendation')} | Save ${rec.get('monthly_savings', 0):,.0f}/mo"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown(f"**Category:** {rec.get('category', 'N/A')}")
                st.markdown(f"**Current Cost:** ${rec.get('current_cost', 0):,.0f}/mo")
                st.markdown(f"**Projected Cost:** ${rec.get('projected_cost', 0):,.0f}/mo")
                st.markdown(f"**Annual Savings:** ${rec.get('annual_savings', 0):,.0f}")
            
            with col2:
                st.markdown(f"**Effort:** {effort_color} {rec.get('effort', 'N/A').title()}")
                st.markdown(f"**Risk:** {rec.get('risk', 'N/A').title()}")
                st.markdown(f"**AWS Services:** {', '.join(rec.get('aws_services_involved', []))}")
            
            if rec.get('implementation_steps'):
                st.markdown("**Implementation Steps:**")
                for step in rec['implementation_steps']:
                    st.markdown(f"- {step}")


def render_sustainability_insights(results: Dict):
    """Render sustainability insights"""
    
    if "sustainability_insights" not in results:
        return
    
    sustainability = results["sustainability_insights"]
    
    st.markdown("### 🌱 Sustainability & Carbon Footprint")
    
    col1, col2 = st.columns(2)
    
    with col1:
        carbon = sustainability.get('estimated_carbon_footprint_kg', 0)
        st.metric(
            "Estimated Carbon Footprint",
            f"{carbon:,.0f} kg CO₂/month",
            delta="Track & reduce"
        )
        
        st.markdown("**Carbon Reduction Opportunities:**")
        for opp in sustainability.get('carbon_reduction_opportunities', []):
            st.markdown(f"- 🌿 {opp}")
    
    with col2:
        st.markdown("**Green Region Recommendations:**")
        for region in sustainability.get('green_region_recommendations', []):
            st.markdown(f"- 🌍 {region}")


def render_finops_maturity(results: Dict):
    """Render FinOps maturity assessment"""
    
    if "finops_maturity_assessment" not in results:
        return
    
    maturity = results["finops_maturity_assessment"]
    
    st.markdown("### 📈 FinOps Maturity Assessment")
    
    score = maturity.get('score', 0)
    level = maturity.get('current_level', 'Crawl')
    
    # Progress bar
    st.progress(score / 100)
    st.markdown(f"**Current Level: {level}** (Score: {score}/100)")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Strengths:**")
        for strength in maturity.get('strengths', []):
            st.markdown(f"- ✅ {strength}")
    
    with col2:
        st.markdown("**Improvement Areas:**")
        for area in maturity.get('improvement_areas', []):
            st.markdown(f"- 🎯 {area}")
    
    st.markdown("**Next Steps:**")
    for step in maturity.get('next_steps', []):
        st.markdown(f"- 📌 {step}")


def render_finops_module(client: Optional[anthropic.Anthropic]):
    """Main renderer for the FinOps module"""
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #1a5f2a 0%, #2d8a3e 100%); padding: 1.5rem; border-radius: 12px; margin-bottom: 1.5rem;">
        <h2 style="color: white; margin: 0;">💰 Enterprise FinOps & Cost Intelligence</h2>
        <p style="color: #90EE90; margin: 0.5rem 0 0 0;">AI-Powered Cost Optimization & Sustainability</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize session state
    if "finops_results" not in st.session_state:
        st.session_state.finops_results = None
    
    # Create tabs
    tabs = st.tabs([
        "📊 Cost Analysis",
        "🚨 Anomaly Detection",
        "💡 Optimizations",
        "🎯 Budget Management",
        "🌱 Sustainability",
        "📈 FinOps Maturity",
        "🤖 AI Cost Advisor"
    ])
    
    # Tab 1: Cost Analysis
    with tabs[0]:
        st.markdown("### 📊 Cost Analysis Dashboard")
        
        # Input method selection
        input_method = st.radio(
            "Data Source",
            ["Demo Data", "Upload Cost Export", "Manual Input"],
            horizontal=True
        )
        
        cost_data = None
        
        if input_method == "Demo Data":
            cost_data = generate_demo_cost_data()
            st.success("✅ Demo data loaded")
            
            # Show data preview
            with st.expander("📋 View Cost Data"):
                st.json(cost_data)
        
        elif input_method == "Upload Cost Export":
            uploaded = st.file_uploader(
                "Upload AWS Cost Explorer export (JSON/CSV)",
                type=["json", "csv"]
            )
            if uploaded:
                try:
                    if uploaded.name.endswith('.json'):
                        cost_data = json.load(uploaded)
                    else:
                        st.warning("CSV support coming soon. Please use JSON format.")
                except Exception as e:
                    st.error(f"Failed to parse file: {e}")
        
        else:  # Manual Input
            cost_data = {
                "total_cost": st.number_input("Total Monthly Cost ($)", value=25000),
                "period": "Last 30 Days",
                "by_service": {
                    "EC2": st.number_input("EC2 Cost", value=8000),
                    "RDS": st.number_input("RDS Cost", value=5000),
                    "S3": st.number_input("S3 Cost", value=2000),
                    "Other": st.number_input("Other Services", value=10000)
                }
            }
        
        # Analysis button
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            analyze_btn = st.button(
                "🔍 Analyze Costs with AI",
                type="primary",
                use_container_width=True,
                disabled=not (cost_data and client)
            )
        
        if analyze_btn and cost_data and client:
            with st.spinner("🤖 AI analyzing your cost data..."):
                results = analyze_costs_with_ai(client, cost_data)
                if "error" not in results:
                    st.session_state.finops_results = results
                    st.success("✅ Analysis complete!")
                else:
                    st.error(f"Analysis failed: {results['error']}")
        
        # Show results
        if st.session_state.finops_results:
            render_finops_dashboard(st.session_state.finops_results)
    
    # Tab 2: Anomaly Detection
    with tabs[1]:
        if st.session_state.finops_results:
            render_cost_anomalies(st.session_state.finops_results)
        else:
            st.info("👆 Run cost analysis first to detect anomalies")
    
    # Tab 3: Optimizations
    with tabs[2]:
        if st.session_state.finops_results:
            render_optimization_recommendations(st.session_state.finops_results)
        else:
            st.info("👆 Run cost analysis first to get optimization recommendations")
    
    # Tab 4: Budget Management
    with tabs[3]:
        st.markdown("### 🎯 Budget Management")
        
        budgets = [
            {"name": "Production", "budget": 15000, "spent": 12500, "forecast": 14800},
            {"name": "Staging", "budget": 5000, "spent": 4200, "forecast": 5100},
            {"name": "Development", "budget": 3000, "spent": 2100, "forecast": 2500},
            {"name": "Overall", "budget": 25000, "spent": 19800, "forecast": 23400}
        ]
        
        for budget in budgets:
            utilization = (budget["spent"] / budget["budget"]) * 100
            forecast_pct = (budget["forecast"] / budget["budget"]) * 100
            
            status = "✅" if forecast_pct <= 100 else "⚠️" if forecast_pct <= 110 else "🚨"
            
            with st.expander(f"{status} {budget['name']} - {utilization:.0f}% utilized"):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Budget", f"${budget['budget']:,}")
                with col2:
                    st.metric("Spent", f"${budget['spent']:,}")
                with col3:
                    st.metric("Forecast", f"${budget['forecast']:,}", 
                             delta=f"{forecast_pct-100:+.0f}%" if forecast_pct > 100 else "On Track")
                
                st.progress(min(utilization / 100, 1.0))
    
    # Tab 5: Sustainability
    with tabs[4]:
        if st.session_state.finops_results:
            render_sustainability_insights(st.session_state.finops_results)
        else:
            st.info("👆 Run cost analysis first to see sustainability insights")
    
    # Tab 6: FinOps Maturity
    with tabs[5]:
        if st.session_state.finops_results:
            render_finops_maturity(st.session_state.finops_results)
        else:
            # Show maturity model reference
            st.markdown("### 📈 FinOps Maturity Model")
            
            for level_key, level in FINOPS_MATURITY_MODEL.items():
                with st.expander(f"**{level['name']}** - {level['description']}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("**Characteristics:**")
                        for char in level['characteristics']:
                            st.markdown(f"- {char}")
                    with col2:
                        st.markdown("**Target Capabilities:**")
                        for cap in level['target_capabilities']:
                            st.markdown(f"- 🎯 {cap}")
    
    # Tab 7: AI Cost Advisor
    with tabs[6]:
        st.markdown("### 🤖 AI Cost Advisor")
        st.markdown("Ask questions about your cloud costs and get AI-powered insights.")
        
        # Quick questions
        st.markdown("**Quick Questions:**")
        quick_questions = [
            "How can I reduce my EC2 costs?",
            "What's driving my data transfer charges?",
            "Should I buy Reserved Instances?",
            "How can I improve my tagging strategy?",
            "What's my projected spend for next quarter?"
        ]
        
        col1, col2 = st.columns(2)
        for i, q in enumerate(quick_questions):
            with col1 if i % 2 == 0 else col2:
                if st.button(f"💬 {q}", key=f"quick_q_{i}"):
                    st.session_state.finops_query = q
        
        query = st.text_area(
            "Your question:",
            value=st.session_state.get('finops_query', ''),
            placeholder="Ask anything about cost optimization...",
            height=100
        )
        
        if st.button("🔍 Ask AI", type="primary") and query and client:
            cost_data = generate_demo_cost_data()
            with st.spinner("🤖 Thinking..."):
                results = analyze_costs_with_ai(client, cost_data, query)
                if "error" not in results:
                    st.markdown("### 💡 AI Response")
                    st.json(results)
                else:
                    st.error(f"Query failed: {results['error']}")


# Export
__all__ = ['render_finops_module', 'FINOPS_MATURITY_MODEL', 'COST_CATEGORIES']
