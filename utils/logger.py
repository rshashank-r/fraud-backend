"""
Structured logging with correlation IDs for request tracing.

This module provides a structured logging setup with correlation IDs,
enabling easy tracking of requests across the application.
"""

import logging
import uuid
from flask import g, request, has_request_context
from functools import wraps
from datetime import datetime


class CorrelationIdFilter(logging.Filter):
    """Add correlation ID to log records."""
    
    def filter(self, record):
        if has_request_context():
            record.correlation_id = getattr(g, 'correlation_id', 'N/A')
            record.user_id = getattr(g, 'user_id', 'anonymous')
            record.endpoint = request.endpoint or 'unknown'
            record.method = request.method
        else:
            record.correlation_id = 'N/A'
            record.user_id = 'system'
            record.endpoint = 'system'
            record.method = 'N/A'
        return True


class RequestFormatter(logging.Formatter):
    """Custom formatter with correlation ID and structured data."""
    
    def format(self, record):
        # Add timestamp in ISO format
        record.timestamp = datetime.utcnow().isoformat()
        
        # Format: [timestamp] CORRELATION_ID LEVEL [endpoint] user_id - message
        log_format = (
            '[%(timestamp)s] %(correlation_id)s %(levelname)-8s '
            '[%(endpoint)s] %(user_id)s - %(message)s'
        )
        
        formatter = logging.Formatter(log_format)
        return formatter.format(record)


def setup_logging(app):
    """
    Configure structured logging for the application.
    
    Args:
        app: Flask application instance
    """
    # Clear existing handlers
    app.logger.handlers.clear()
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Add custom formatter and filter
    console_handler.setFormatter(RequestFormatter())
    console_handler.addFilter(CorrelationIdFilter())
    
    # Add handler to app logger
    app.logger.addHandler(console_handler)
    app.logger.setLevel(logging.INFO)
    
    # Log startup
    app.logger.info("Structured logging initialized")


def log_request_info(app):
    """
    Middleware to log request information.
    
    Args:
        app: Flask application instance
    """
    
    @app.before_request
    def before_request_logging():
        """Generate correlation ID and log request start."""
        # Generate or use existing correlation ID
        g.correlation_id = request.headers.get('X-Correlation-ID', str(uuid.uuid4()))
        
        # Extract user ID if authenticated
        try:
            from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
            verify_jwt_in_request(optional=True)
            g.user_id = get_jwt_identity() or 'anonymous'
        except:
            g.user_id = 'anonymous'
        
        # Log request start
        app.logger.info(
            f"Request started: {request.method} {request.path} "
            f"from {request.remote_addr}"
        )
    
    @app.after_request
    def after_request_logging(response):
        """Log request completion."""
        app.logger.info(
            f"Request completed: {request.method} {request.path} "
            f"status={response.status_code}"
        )
        
        # Add correlation ID to response headers for client-side tracing
        response.headers['X-Correlation-ID'] = g.get('correlation_id', 'N/A')
        
        return response


def log_with_context(logger, level, message, **kwargs):
    """
    Log message with additional context.
    
    Args:
        logger: Logger instance
        level: Log level (INFO, WARNING, ERROR, etc.)
        message: Log message
        **kwargs: Additional context to include in log
    """
    context_str = " | ".join([f"{k}={v}" for k, v in kwargs.items()])
    full_message = f"{message} | {context_str}" if context_str else message
    
    log_func = getattr(logger, level.lower())
    log_func(full_message)


def log_exception(logger, exc, **kwargs):
    """
    Log exception with context.
    
    Args:
        logger: Logger instance
        exc: Exception instance
        **kwargs: Additional context
    """
    log_with_context(
        logger,
        'ERROR',
        f"Exception: {exc.__class__.__name__}: {str(exc)}",
        **kwargs
    )
    
    # Log stack trace for debugging
    logger.exception(exc)
