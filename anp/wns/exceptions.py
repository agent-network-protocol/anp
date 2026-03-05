"""WNS (WBA Name Space) exception hierarchy.

Mirrors the DidWbaVerifierError pattern: each exception carries an HTTP-like
status_code so that callers (e.g. FastAPI handlers) can translate directly.
"""


class WnsError(Exception):
    """Root exception for all WNS operations."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


class HandleValidationError(WnsError):
    """Handle format is invalid (bad local-part, missing domain, etc.)."""

    def __init__(self, message: str):
        super().__init__(message, status_code=400)


class HandleNotFoundError(WnsError):
    """Handle does not exist on the provider (HTTP 404)."""

    def __init__(self, message: str):
        super().__init__(message, status_code=404)


class HandleGoneError(WnsError):
    """Handle has been permanently revoked (HTTP 410)."""

    def __init__(self, message: str):
        super().__init__(message, status_code=410)


class HandleMovedError(WnsError):
    """Handle has been migrated to a new provider (HTTP 301).

    Attributes:
        redirect_url: The new resolution endpoint URL.
    """

    def __init__(self, message: str, redirect_url: str):
        super().__init__(message, status_code=301)
        self.redirect_url = redirect_url


class HandleResolutionError(WnsError):
    """Network or protocol error during handle resolution."""

    def __init__(self, message: str):
        super().__init__(message, status_code=502)


class HandleBindingError(WnsError):
    """Bidirectional binding verification failed."""

    def __init__(self, message: str):
        super().__init__(message, status_code=400)


class WbaUriParseError(WnsError):
    """wba:// URI format is invalid."""

    def __init__(self, message: str):
        super().__init__(message, status_code=400)
