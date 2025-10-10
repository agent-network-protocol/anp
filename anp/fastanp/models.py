"""
Pydantic models for ANP protocol data structures.

This module defines the data models used in the Agent Network Protocol,
including Agent Description, Information items, Interface items, and related structures.
"""

from datetime import UTC, datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Owner(BaseModel):
    """Owner information for an agent."""
    
    type: str = Field(default="Organization", description="Type of owner (Person, Organization, etc.)")
    name: str = Field(description="Name of the owner")
    url: Optional[str] = Field(default=None, description="Owner's website URL")
    email: Optional[str] = Field(default=None, description="Owner's email address")


class SecurityDefinition(BaseModel):
    """Security definition for authentication."""
    
    scheme: str = Field(description="Authentication scheme (e.g., didwba)")
    in_: str = Field(alias="in", description="Where the auth token is passed (e.g., header)")
    name: str = Field(description="Name of the header/parameter")


class Proof(BaseModel):
    """Cryptographic proof for document integrity."""
    
    type: str = Field(description="Signature type")
    created: str = Field(description="Creation timestamp")
    proofPurpose: str = Field(description="Purpose of the proof")
    verificationMethod: str = Field(description="DID verification method used")
    challenge: Optional[str] = Field(default=None, description="Challenge string")
    proofValue: str = Field(description="Base58-encoded signature value")


class InformationItem(BaseModel):
    """Represents an Information item in the agent description."""
    
    type: str = Field(description="Type of information (Product, Information, VideoObject, etc.)")
    description: str = Field(description="Description of this information")
    url: str = Field(description="URL where the information can be accessed")


class InterfaceItem(BaseModel):
    """Represents an Interface item in the agent description."""
    
    type: str = Field(description="Type of interface (StructuredInterface, NaturalLanguageInterface, etc.)")
    protocol: str = Field(description="Protocol used (openrpc, YAML, MCP, etc.)")
    description: str = Field(description="Description of this interface")
    url: Optional[str] = Field(default=None, description="URL to the interface specification")
    content: Optional[Dict[str, Any]] = Field(default=None, description="Embedded interface content (for embedded mode)")
    version: Optional[str] = Field(default=None, description="Interface version")
    humanAuthorization: Optional[bool] = Field(default=None, description="Whether human authorization is required")


class AgentDescription(BaseModel):
    """Complete Agent Description document following ANP specification."""
    
    protocolType: str = Field(default="ANP", description="Protocol type identifier")
    protocolVersion: str = Field(default="1.0.0", description="ANP protocol version")
    type: str = Field(default="AgentDescription", description="Document type")
    url: str = Field(description="URL of this agent description")
    name: str = Field(description="Agent name")
    did: str = Field(description="DID identifier for this agent")
    owner: Optional[Owner] = Field(default=None, description="Owner information")
    description: str = Field(description="Agent description")
    created: str = Field(default_factory=lambda: datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ'), 
                        description="Creation timestamp")
    securityDefinitions: Optional[Dict[str, SecurityDefinition]] = Field(
        default=None, 
        description="Security scheme definitions"
    )
    security: Optional[str] = Field(default=None, description="Active security scheme reference")
    Infomations: Optional[List[InformationItem]] = Field(
        default=None, 
        description="List of information resources",
        alias="Infomations"  # Note: ANP spec uses "Infomations" (with typo)
    )
    interfaces: Optional[List[InterfaceItem]] = Field(
        default=None, 
        description="List of agent interfaces"
    )
    proof: Optional[Proof] = Field(default=None, description="Cryptographic proof")

    class Config:
        populate_by_name = True
        json_schema_extra = {
            "example": {
                "protocolType": "ANP",
                "protocolVersion": "1.0.0",
                "type": "AgentDescription",
                "url": "https://example.com/ad.json",
                "name": "Example Agent",
                "did": "did:wba:example.com:agent:example",
                "description": "An example ANP agent"
            }
        }


class OpenRPCInfo(BaseModel):
    """OpenRPC info section."""
    
    title: str = Field(description="API title")
    version: str = Field(description="API version")
    description: str = Field(description="API description")
    x_anp_protocol_type: str = Field(
        default="ANP", 
        alias="x-anp-protocol-type",
        description="ANP protocol type"
    )
    x_anp_protocol_version: str = Field(
        default="1.0.0",
        alias="x-anp-protocol-version", 
        description="ANP protocol version"
    )

    class Config:
        populate_by_name = True


class OpenRPCSecurityScheme(BaseModel):
    """OpenRPC security scheme definition."""
    
    type: str = Field(default="http", description="Security type")
    scheme: str = Field(default="bearer", description="Security scheme")
    bearerFormat: str = Field(default="DID-WBA", description="Bearer token format")
    description: Optional[str] = Field(
        default="DID-WBA authentication scheme",
        description="Security scheme description"
    )


class OpenRPCServer(BaseModel):
    """OpenRPC server definition."""
    
    name: Optional[str] = Field(default=None, description="Server name")
    url: str = Field(description="Server URL")
    description: Optional[str] = Field(default=None, description="Server description")


class OpenRPCParam(BaseModel):
    """OpenRPC method parameter."""
    
    name: str = Field(description="Parameter name")
    description: str = Field(description="Parameter description")
    required: bool = Field(default=True, description="Whether parameter is required")
    schema_: Dict[str, Any] = Field(alias="schema", description="Parameter JSON Schema")

    class Config:
        populate_by_name = True


class OpenRPCResult(BaseModel):
    """OpenRPC method result."""
    
    name: str = Field(description="Result name")
    description: str = Field(description="Result description")
    schema_: Dict[str, Any] = Field(alias="schema", description="Result JSON Schema")

    class Config:
        populate_by_name = True


class OpenRPCMethod(BaseModel):
    """OpenRPC method definition."""
    
    name: str = Field(description="Method name")
    summary: Optional[str] = Field(default=None, description="Method summary")
    description: str = Field(description="Method description")
    params: List[OpenRPCParam] = Field(default_factory=list, description="Method parameters")
    result: OpenRPCResult = Field(description="Method result")


class OpenRPCDocument(BaseModel):
    """Complete OpenRPC 1.3.2 document."""
    
    openrpc: str = Field(default="1.3.2", description="OpenRPC version")
    info: OpenRPCInfo = Field(description="API information")
    security: Optional[List[Dict[str, List]]] = Field(
        default=None,
        description="Security requirements"
    )
    servers: List[OpenRPCServer] = Field(default_factory=list, description="API servers")
    methods: List[OpenRPCMethod] = Field(default_factory=list, description="API methods")
    components: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Reusable components (schemas, securitySchemes)"
    )

    class Config:
        populate_by_name = True

