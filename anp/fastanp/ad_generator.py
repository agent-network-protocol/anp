"""
Agent Description (ad.json) common header generator.

Generates the common header fields for ANP-compliant Agent Description documents.
Users can then add their own Information and Interface items.
"""

from datetime import UTC, datetime
from typing import Any, Dict, Optional

from .models import Owner
from .utils import normalize_agent_domain


class ADGenerator:
    """Generates Agent Description common header following ANP specification."""
    
    def __init__(
        self,
        name: str,
        description: str,
        did: str,
        agent_domain: str,
        agent_description_path: str = "/ad.json",
        owner: Optional[Dict[str, str]] = None,
        protocol_version: str = "1.0.0"
    ):
        """
        Initialize AD generator.

        Args:
            name: Agent name
            description: Agent description
            did: DID identifier
            agent_domain: Agent domain (支持多种格式，会自动规范化)
            agent_description_path: Agent description path (包含ad.json)
            owner: Owner information dictionary
            protocol_version: ANP protocol version
        """
        self.name = name
        self.description = description
        self.did = did

        # 规范化 agent_domain，处理各种输入格式
        self.agent_domain, _ = normalize_agent_domain(agent_domain)

        self.agent_description_path = agent_description_path
        self.owner = Owner(**owner) if owner else None
        self.protocol_version = protocol_version
    
    def generate_common_header(
        self,
        ad_url: Optional[str] = None,
        require_auth: bool = True
    ) -> Dict[str, Any]:
        """
        Generate common header fields for Agent Description.

        Users can extend this with their own Infomations and interfaces.

        Args:
            ad_url: URL of the ad.json endpoint (defaults to agent_domain + agent_description_path)
            require_auth: Whether to include security definitions

        Returns:
            Agent Description common header dictionary
        """
        # Determine ad.json URL
        if ad_url is None:
            ad_url = f"{self.agent_domain}{self.agent_description_path}"
        
        # Build base agent description
        ad_data = {
            "protocolType": "ANP",
            "protocolVersion": self.protocol_version,
            "type": "AgentDescription",
            "url": ad_url,
            "name": self.name,
            "did": self.did,
            "description": self.description,
            "created": datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')
        }
        
        # Add owner if provided
        if self.owner:
            ad_data["owner"] = self.owner.model_dump(exclude_none=True)
        
        # Add security definitions if authentication is required
        ad_data["securityDefinitions"] = {
            "didwba_sc": {
                "scheme": "didwba",
                "in": "header",
                "name": "Authorization"
            }
        }
        ad_data["security"] = "didwba_sc"
        
        return ad_data
