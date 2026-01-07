"""
Request/Response schemas for API validation and documentation.

This module provides Marshmallow schemas for validating API requests
and documenting API responses for Swagger/OpenAPI.
"""

from marshmallow import Schema, fields, validate, validates, ValidationError


# ========== AUTHENTICATION SCHEMAS ==========

class LoginRequestSchema(Schema):
    """Schema for login request."""
    email = fields.Email(required=True, error_messages={'required': 'Email is required'})
    password = fields.Str(required=True, validate=validate.Length(min=8), 
                          error_messages={'required': 'Password is required'})
    captcha_challenge_id = fields.Str(required=True)
    captcha_answer = fields.Int(required=True)
    lat = fields.Float(required=False, allow_none=True)
    lon = fields.Float(required=False, allow_none=True)


class LoginResponseSchema(Schema):
    """Schema for login response."""
    access_token = fields.Str(required=False)
    role = fields.Str(required=False)
    verification_required = fields.Str(required=False)
    message = fields.Str(required=False)
    risk_score = fields.Float(required=False)
    risk_factors = fields.List(fields.Str(), required=False)


class RegisterRequestSchema(Schema):
    """Schema for registration request."""
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=8))
    phone_number = fields.Str(required=False, allow_none=True)
    captcha_challenge_id = fields.Str(required=True)
    captcha_answer = fields.Int(required=True)


class OTPVerificationSchema(Schema):
    """Schema for OTP verification."""
    email = fields.Email(required=True)
    otp = fields.Str(required=True, validate=validate.Length(equal=6))


# ========== TRANSACTION SCHEMAS ==========

class TransactionRequestSchema(Schema):
    """Schema for transaction request."""
    amount = fields.Float(required=True, validate=validate.Range(min=0.01))
    receiver_account = fields.Str(required=True)
    transaction_type = fields.Str(required=True, 
                                  validate=validate.OneOf(['PAYMENT', 'TRANSFER', 'WITHDRAWAL']))
    nonce = fields.Str(required=True)
    lat = fields.Float(required=False, allow_none=True)
    lon = fields.Float(required=False, allow_none=True)


class TransactionResponseSchema(Schema):
    """Schema for transaction response."""
    transaction_id = fields.Str()
    status = fields.Str()
    risk_score = fields.Float()
    message = fields.Str()
    otp_required = fields.Bool()


# ========== ERROR SCHEMAS ==========

class ErrorResponseSchema(Schema):
    """Schema for error responses."""
    error = fields.Str(required=True)
    message = fields.Str(required=True)
    details = fields.Dict(required=False)
    status_code = fields.Int(required=False)


# ========== COMMON SCHEMAS ==========

class SuccessResponseSchema(Schema):
    """Schema for generic success responses."""
    message = fields.Str()
    data = fields.Dict(required=False)


class PaginationSchema(Schema):
    """Schema for pagination parameters."""
    page = fields.Int(required=False, validate=validate.Range(min=1), load_default=1)
    per_page = fields.Int(required=False, validate=validate.Range(min=1, max=100), load_default=10)
