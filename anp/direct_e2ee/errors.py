"""Errors for the direct_e2ee module."""


class DirectE2eeError(Exception):
    """Raised when direct E2EE processing fails."""

    def __init__(self, message: str, code: str = "direct_e2ee_error") -> None:
        super().__init__(message)
        self.code = code
