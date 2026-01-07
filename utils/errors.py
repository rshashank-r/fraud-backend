"""
Custom exception classes for centralized error handling.

This module provides a hierarchy of exceptions for different API error scenarios,
enabling consistent error responses and better error tracking.
"""

class APIError(Exception):
    """Base exception for all API errors."""
    status_code = 500
    
    def __init__(self, message="An error occurred", details=None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self):
        """Convert exception to dictionary for JSON response."""
        return {
            'error': self.__class__.__name__,
            'message': self.message,
            'details': self.details,
            'status_code': self.status_code
        }


class ValidationError(APIError):
    """Raised when request validation fails."""
    status_code = 400
    
    def __init__(self, message="Validation failed", details=None):
        super().__init__(message, details)


class AuthenticationError(APIError):
    """Raised when authentication fails."""
    status_code = 401
    
    def __init__(self, message="Authentication required", details=None):
        super().__init__(message, details)


class AuthorizationError(APIError):
    """Raised when user lacks permissions."""
    status_code = 403
    
    def __init__(self, message="Insufficient permissions", details=None):
        super().__init__(message, details)


class NotFoundError(APIError):
    """Raised when resource is not found."""
    status_code = 404
    
    def __init__(self, message="Resource not found", details=None):
        super().__init__(message, details)


class ConflictError(APIError):
    """Raised when resource conflict occurs (e.g., duplicate email)."""
    status_code = 409
    
    def __init__(self, message="Resource conflict", details=None):
        super().__init__(message, details)


class RateLimitError(APIError):
    """Raised when rate limit is exceeded."""
    status_code = 429
    
    def __init__(self, message="Rate limit exceeded", details=None):
        super().__init__(message, details)


class InternalServerError(APIError):
    """Raised for unexpected server errors."""
    status_code = 500
    
    def __init__(self, message="Internal server error", details=None):
        super().__init__(message, details)


class ServiceUnavailableError(APIError):
    """Raised when a service is temporarily unavailable."""
    status_code = 503
    
    def __init__(self, message="Service temporarily unavailable", details=None):
        super().__init__(message, details)


class DatabaseError(APIError):
    """Raised when database operation fails."""
    status_code = 500
    
    def __init__(self, message="Database error occurred", details=None):
        super().__init__(message, details)


class ExternalServiceError(APIError):
    """Raised when external service call fails."""
    status_code = 502
    
    def __init__(self, message="External service error", details=None):
        super().__init__(message, details)
