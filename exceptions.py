"""Custom exception classes for Deep Audit Agent"""


class AuditError(Exception):
    """Base exception for audit-related errors"""
    pass


class LLMError(AuditError):
    """Errors related to LLM API calls"""
    pass


class DatabaseError(AuditError):
    """Errors related to database operations"""
    pass


class SlitherError(AuditError):
    """Errors related to Slither analysis"""
    pass


class ConfigError(AuditError):
    """Errors related to configuration"""
    pass


class ValidationError(AuditError):
    """Errors during validation"""
    pass


class CacheError(AuditError):
    """Errors related to caching"""
    pass
