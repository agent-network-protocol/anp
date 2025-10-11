"""
Context and Session management for FastANP.

Provides automatic context injection for interface methods with session management
based on DID and Access Token.
"""

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import Request

logger = logging.getLogger(__name__)


class Session:
    """
    Represents a user session identified by DID and Access Token.
    """
    
    def __init__(self, session_id: str, did: str):
        """
        Initialize session.
        
        Args:
            session_id: Unique session identifier
            did: DID of the session owner
        """
        self.id = session_id
        self.did = did
        self.created_at = datetime.now()
        self.last_accessed = datetime.now()
        self.data: Dict[str, Any] = {}
    
    def touch(self):
        """Update last accessed time."""
        self.last_accessed = datetime.now()
    
    def set(self, key: str, value: Any):
        """
        Set session data.
        
        Args:
            key: Data key
            value: Data value
        """
        self.data[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get session data.
        
        Args:
            key: Data key
            default: Default value if key not found
            
        Returns:
            Session data value or default
        """
        return self.data.get(key, default)
    
    def clear(self):
        """Clear all session data."""
        self.data.clear()


class Context:
    """
    Request context automatically injected into interface methods.
    
    Contains session information, authentication results, and request details.
    """
    
    def __init__(
        self,
        session: Session,
        did: str,
        request: Request,
        auth_result: Optional[dict] = None
    ):
        """
        Initialize context.
        
        Args:
            session: Session object
            did: Requester's DID
            request: FastAPI Request object
            auth_result: Authentication result dictionary
        """
        self.session = session
        self.did = did
        self.request = request
        self.auth_result = auth_result or {}
    
    @property
    def headers(self) -> dict:
        """Get request headers."""
        return dict(self.request.headers)
    
    @property
    def client_host(self) -> Optional[str]:
        """Get client host."""
        if self.request.client:
            return self.request.client.host
        return None


class SessionManager:
    """
    Manages session lifecycle and storage.
    
    Sessions are identified by a hash of DID + Access Token.
    """
    
    def __init__(
        self,
        session_timeout_minutes: int = 60,
        cleanup_interval_minutes: int = 10
    ):
        """
        Initialize session manager.
        
        Args:
            session_timeout_minutes: Session timeout in minutes
            cleanup_interval_minutes: Cleanup interval in minutes
        """
        self.sessions: Dict[str, Session] = {}
        self.session_timeout = timedelta(minutes=session_timeout_minutes)
        self.cleanup_interval = timedelta(minutes=cleanup_interval_minutes)
        self.last_cleanup = datetime.now()
    
    def _generate_session_id(self, did: str) -> str:
        """
        Generate session ID from DID only.
        
        Args:
            did: DID identifier
            
        Returns:
            Session ID hash
        """
        return hashlib.sha256(did.encode()).hexdigest()
    
    def get_or_create(
        self,
        did: str,
        anonymous: bool = False
    ) -> Session:
        """
        Get existing session or create new one based on DID.
        
        Args:
            did: DID identifier
            anonymous: Whether this is an anonymous session
            
        Returns:
            Session object
        """
        # Cleanup old sessions periodically
        self._cleanup_if_needed()
        
        # Generate session ID from DID
        session_id = self._generate_session_id(did)
        
        # Get or create session
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.touch()
            logger.debug(f"Retrieved existing session: {session_id[:8]}... for DID: {did}")
        else:
            session = Session(session_id, did)
            self.sessions[session_id] = session
            logger.info(f"Created new session: {session_id[:8]}... for DID: {did}")
        
        return session
    
    def get(self, session_id: str) -> Optional[Session]:
        """
        Get session by ID.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session object or None
        """
        session = self.sessions.get(session_id)
        if session:
            session.touch()
        return session
    
    def remove(self, session_id: str):
        """
        Remove session by ID.
        
        Args:
            session_id: Session identifier
        """
        if session_id in self.sessions:
            del self.sessions[session_id]
            logger.info(f"Removed session: {session_id[:8]}...")
    
    def _cleanup_if_needed(self):
        """Cleanup expired sessions if needed."""
        now = datetime.now()
        if now - self.last_cleanup < self.cleanup_interval:
            return
        
        self.last_cleanup = now
        expired_ids = []
        
        for session_id, session in self.sessions.items():
            if now - session.last_accessed > self.session_timeout:
                expired_ids.append(session_id)
        
        for session_id in expired_ids:
            self.remove(session_id)
        
        if expired_ids:
            logger.info(f"Cleaned up {len(expired_ids)} expired sessions")
    
    def clear_all(self):
        """Clear all sessions."""
        count = len(self.sessions)
        self.sessions.clear()
        logger.info(f"Cleared all {count} sessions")

