"""
Secrets Helper Module
Centralizes reading of credentials from Streamlit secrets

Supports multiple credential sources:
1. Streamlit secrets (secrets.toml or Streamlit Cloud)
2. Environment variables
3. Manual input via UI
"""

import streamlit as st
import os
from typing import Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class AWSCredentials:
    """AWS Credentials container"""
    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = None
    region: str = "us-east-1"
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    source: str = "unknown"


@dataclass 
class AnthropicCredentials:
    """Anthropic API credentials container"""
    api_key: str
    source: str = "unknown"


def get_anthropic_api_key() -> Optional[str]:
    """
    Get Anthropic API key from available sources.
    
    Priority order:
    1. Streamlit secrets (ANTHROPIC_API_KEY)
    2. Streamlit secrets nested (anthropic.api_key)
    3. Environment variable (ANTHROPIC_API_KEY)
    4. Session state (if manually entered)
    
    Returns:
        API key string or None if not found
    """
    api_key = None
    source = None
    
    # Try Streamlit secrets - flat key
    try:
        if hasattr(st, 'secrets') and 'ANTHROPIC_API_KEY' in st.secrets:
            api_key = st.secrets['ANTHROPIC_API_KEY']
            source = "streamlit_secrets"
    except Exception:
        pass
    
    # Try Streamlit secrets - nested format
    if not api_key:
        try:
            if hasattr(st, 'secrets') and 'anthropic' in st.secrets:
                api_key = st.secrets['anthropic'].get('api_key')
                source = "streamlit_secrets_nested"
        except Exception:
            pass
    
    # Try environment variable
    if not api_key:
        api_key = os.environ.get('ANTHROPIC_API_KEY')
        if api_key:
            source = "environment"
    
    # Try session state (manual input)
    if not api_key and 'anthropic_api_key' in st.session_state:
        api_key = st.session_state.anthropic_api_key
        source = "session_state"
    
    if api_key:
        # Store source for debugging
        st.session_state.anthropic_key_source = source
    
    return api_key


def get_aws_credentials() -> Optional[AWSCredentials]:
    """
    Get AWS credentials from available sources.
    
    Priority order:
    1. Streamlit secrets (aws.access_key_id, etc.)
    2. Environment variables (AWS_ACCESS_KEY_ID, etc.)
    3. Session state (if manually entered)
    
    Returns:
        AWSCredentials object or None if not found
    """
    access_key = None
    secret_key = None
    session_token = None
    region = "us-east-1"
    role_arn = None
    external_id = None
    source = "unknown"
    
    # Try Streamlit secrets
    try:
        if hasattr(st, 'secrets') and 'aws' in st.secrets:
            aws_secrets = st.secrets['aws']
            access_key = aws_secrets.get('access_key_id')
            secret_key = aws_secrets.get('secret_access_key')
            session_token = aws_secrets.get('session_token')
            region = aws_secrets.get('default_region', 'us-east-1')
            
            # Check for role assumption config
            if 'assume_role' in aws_secrets:
                role_arn = aws_secrets['assume_role'].get('role_arn')
                external_id = aws_secrets['assume_role'].get('external_id')
            
            if access_key and secret_key:
                source = "streamlit_secrets"
    except Exception:
        pass
    
    # Try environment variables
    if not access_key:
        access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        session_token = os.environ.get('AWS_SESSION_TOKEN')
        region = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
        role_arn = os.environ.get('AWS_ROLE_ARN')
        
        if access_key and secret_key:
            source = "environment"
    
    # Try session state (manual input)
    if not access_key and 'aws_access_key' in st.session_state:
        access_key = st.session_state.get('aws_access_key')
        secret_key = st.session_state.get('aws_secret_key')
        session_token = st.session_state.get('aws_session_token')
        region = st.session_state.get('aws_region', 'us-east-1')
        
        if access_key and secret_key:
            source = "session_state"
    
    if access_key and secret_key:
        return AWSCredentials(
            access_key_id=access_key,
            secret_access_key=secret_key,
            session_token=session_token,
            region=region,
            role_arn=role_arn,
            external_id=external_id,
            source=source
        )
    
    return None


def get_aws_organization_config() -> Dict:
    """
    Get AWS Organization configuration from secrets.
    
    Returns:
        Dictionary with organization settings
    """
    config = {
        'management_account_id': None,
        'cross_account_role_name': 'OrganizationAccountAccessRole',
        'fallback_roles': ['AWSControlTowerExecution', 'AuditRole'],
        'excluded_accounts': [],
        'excluded_ous': []
    }
    
    try:
        if hasattr(st, 'secrets') and 'aws' in st.secrets:
            if 'organization' in st.secrets['aws']:
                org_config = st.secrets['aws']['organization']
                
                config['management_account_id'] = org_config.get('management_account_id')
                config['cross_account_role_name'] = org_config.get(
                    'cross_account_role_name', 
                    'OrganizationAccountAccessRole'
                )
                
                if 'fallback_roles' in org_config:
                    config['fallback_roles'] = list(org_config['fallback_roles'])
                
                if 'excluded_accounts' in org_config:
                    config['excluded_accounts'] = [
                        a.strip() for a in org_config['excluded_accounts'].split(',')
                    ]
                
                if 'excluded_ous' in org_config:
                    config['excluded_ous'] = [
                        o.strip() for o in org_config['excluded_ous'].split(',')
                    ]
    except Exception:
        pass
    
    return config


def get_aws_regions_config() -> Dict:
    """
    Get AWS regions configuration from secrets.
    
    Returns:
        Dictionary with regions settings
    """
    config = {
        'enabled_regions': None,  # None means all regions
        'disabled_regions': [],
        'global_region': 'us-east-1'
    }
    
    try:
        if hasattr(st, 'secrets') and 'aws' in st.secrets:
            if 'regions' in st.secrets['aws']:
                regions_config = st.secrets['aws']['regions']
                
                if 'enabled_regions' in regions_config:
                    config['enabled_regions'] = list(regions_config['enabled_regions'])
                
                if 'disabled_regions' in regions_config:
                    config['disabled_regions'] = list(regions_config['disabled_regions'])
                
                config['global_region'] = regions_config.get('global_region', 'us-east-1')
    except Exception:
        pass
    
    return config


def get_app_config() -> Dict:
    """
    Get application configuration from secrets.
    
    Returns:
        Dictionary with app settings
    """
    config = {
        'name': 'AWS Well-Architected Advisor',
        'organization_name': '',
        'environment': 'production',
        'debug': False
    }
    
    try:
        if hasattr(st, 'secrets') and 'app' in st.secrets:
            app_config = st.secrets['app']
            config['name'] = app_config.get('name', config['name'])
            config['organization_name'] = app_config.get('organization_name', '')
            config['environment'] = app_config.get('environment', 'production')
            config['debug'] = app_config.get('debug', False)
    except Exception:
        pass
    
    return config


def check_secrets_configured() -> Tuple[bool, bool, Dict]:
    """
    Check which secrets are configured.
    
    Returns:
        Tuple of (anthropic_configured, aws_configured, details_dict)
    """
    anthropic_key = get_anthropic_api_key()
    aws_creds = get_aws_credentials()
    
    details = {
        'anthropic': {
            'configured': bool(anthropic_key),
            'source': st.session_state.get('anthropic_key_source', 'not_found')
        },
        'aws': {
            'configured': bool(aws_creds),
            'source': aws_creds.source if aws_creds else 'not_found',
            'has_role': bool(aws_creds and aws_creds.role_arn) if aws_creds else False
        }
    }
    
    return bool(anthropic_key), bool(aws_creds), details


def render_secrets_status():
    """Render a status indicator for configured secrets"""
    
    anthropic_ok, aws_ok, details = check_secrets_configured()
    
    col1, col2 = st.columns(2)
    
    with col1:
        if anthropic_ok:
            st.success(f"✅ Anthropic API Key ({details['anthropic']['source']})")
        else:
            st.error("❌ Anthropic API Key not configured")
    
    with col2:
        if aws_ok:
            role_info = " + Role" if details['aws']['has_role'] else ""
            st.success(f"✅ AWS Credentials ({details['aws']['source']}{role_info})")
        else:
            st.warning("⚠️ AWS Credentials not configured (optional)")


def render_manual_credentials_input():
    """Render UI for manual credentials input"""
    
    st.markdown("### 🔐 Manual Credentials Input")
    st.info("Enter credentials here if not configured in secrets.toml")
    
    # Anthropic
    with st.expander("🤖 Anthropic API Key", expanded=not get_anthropic_api_key()):
        api_key = st.text_input(
            "Anthropic API Key",
            type="password",
            value=st.session_state.get('anthropic_api_key', ''),
            help="Get your key from https://console.anthropic.com/"
        )
        if api_key:
            st.session_state.anthropic_api_key = api_key
            st.success("✅ API key saved to session")
    
    # AWS
    with st.expander("☁️ AWS Credentials", expanded=not get_aws_credentials()):
        col1, col2 = st.columns(2)
        
        with col1:
            access_key = st.text_input(
                "Access Key ID",
                type="password",
                value=st.session_state.get('aws_access_key', ''),
                help="AWS Access Key ID (starts with AKIA...)"
            )
            if access_key:
                st.session_state.aws_access_key = access_key
        
        with col2:
            secret_key = st.text_input(
                "Secret Access Key",
                type="password",
                value=st.session_state.get('aws_secret_key', ''),
            )
            if secret_key:
                st.session_state.aws_secret_key = secret_key
        
        session_token = st.text_input(
            "Session Token (optional)",
            type="password",
            value=st.session_state.get('aws_session_token', ''),
            help="Required for temporary credentials"
        )
        if session_token:
            st.session_state.aws_session_token = session_token
        
        region = st.selectbox(
            "Default Region",
            ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"],
            index=0
        )
        st.session_state.aws_region = region
        
        if access_key and secret_key:
            st.success("✅ AWS credentials saved to session")


# Export
__all__ = [
    'AWSCredentials',
    'AnthropicCredentials',
    'get_anthropic_api_key',
    'get_aws_credentials',
    'get_aws_organization_config',
    'get_aws_regions_config',
    'get_app_config',
    'check_secrets_configured',
    'render_secrets_status',
    'render_manual_credentials_input'
]
