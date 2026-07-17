"""
Database models for the gaas-gateway application.
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Float
from sqlalchemy.sql import func
from typing import Optional
from app.database import Base


class Gateway(Base):
    """
    Gateway model representing a gateway instance.
    """
    __tablename__ = "gateways"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    endpoint = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class Route(Base):
    """
    Route model representing API routes.
    """
    __tablename__ = "routes"

    id = Column(Integer, primary_key=True, index=True)
    path = Column(String, nullable=False, index=True)
    method = Column(String, nullable=False)  # GET, POST, PUT, DELETE, etc.
    gateway_id = Column(Integer, nullable=False, index=True)
    target_url = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class User(Base):
    """
    User model representing a user in the system.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    api_key = Column(String, unique=True, index=True, nullable=False)
    api_key_revealed = Column(Boolean, default=False, nullable=False)


class Service(Base):
    """
    Service model representing a service endpoint.
    """
    __tablename__ = "services"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    target_url = Column(String, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    watermarking_enabled = Column(Boolean, default=False, nullable=False)


class ApiKey(Base):
    """
    ApiKey model representing API keys for services.
    Supports multiple API keys per service.
    """
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True, nullable=False)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    rate_limit_override = Column(Integer, nullable=True)  # Optional override for rate limit (legacy)
    rate_limit_requests = Column(Integer, nullable=True)  # Optional override: max requests per window
    rate_limit_window_seconds = Column(Integer, nullable=True)  # Optional override: time window in seconds
    price_per_request = Column(Float, default=0.001, nullable=False)  # Billing: price per request in dollars
    total_cost = Column(Float, default=0.0, nullable=False)  # Billing: total cost accumulated for this API key


class UsageLog(Base):
    """
    UsageLog model representing API usage logs.
    """
    __tablename__ = "usage_logs"

    id = Column(Integer, primary_key=True, index=True)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False, index=True)
    api_key = Column(String, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class BotDetectionLog(Base):
    """
    BotDetectionLog model for tracking bot detection results.
    """
    __tablename__ = "bot_detection_logs"

    id = Column(Integer, primary_key=True, index=True)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False, index=True)
    api_key = Column(String, nullable=False, index=True)
    bot_score = Column(Float, nullable=False)  # 0.0 to 1.0
    classification = Column(String, nullable=False)  # human, suspicious, bot
    user_agent = Column(String, nullable=True)
    action_taken = Column(String, nullable=False)  # allowed, flagged, blocked
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ServiceConfig(Base):
    """
    ServiceConfig model for service-level configuration.
    """
    __tablename__ = "service_configs"

    id = Column(Integer, primary_key=True, index=True)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False, unique=True, index=True)
    block_bots_enabled = Column(Boolean, default=False, nullable=False)
    bot_threshold = Column(Float, default=0.7, nullable=False)  # Score threshold for blocking


class RequestHash(Base):
    """
    RequestHash model for cryptographic transparency.
    Stores SHA-256 hash of each API request for auditability.
    """
    __tablename__ = "request_hashes"

    id = Column(Integer, primary_key=True, index=True)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False, index=True)
    api_key_id = Column(Integer, ForeignKey("api_keys.id"), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    request_path = Column(String, nullable=False)
    response_status = Column(Integer, nullable=False)
    hash = Column(String(64), nullable=False, index=True)  # SHA-256 hash (64 hex chars)
    merkle_batch_id = Column(Integer, ForeignKey("merkle_roots.id"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AnomalyScoreLog(Base):
    """
    AnomalyScoreLog persists elevated risk decisions (risk >= LOG threshold)
    from the adaptive anomaly detection pipeline for auditing and the
    security dashboard. Sub-scores are stored so every decision is explainable.
    """
    __tablename__ = "anomaly_scores"

    id = Column(Integer, primary_key=True, index=True)
    api_key_id = Column(Integer, ForeignKey("api_keys.id"), nullable=False, index=True)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False, index=True)
    risk = Column(Float, nullable=False)           # fused risk score [0, 1]
    score_global = Column(Float, nullable=False)   # g: HalfSpaceTrees
    score_perkey = Column(Float, nullable=False)   # p: per-key behavioral
    score_enum = Column(Float, nullable=False)     # e: enumeration (HLL)
    score_auth = Column(Float, nullable=False)     # a: auth-failure abuse
    action = Column(String, nullable=False)        # log / tarpit / block
    endpoint = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class MerkleRoot(Base):
    """
    MerkleRoot model for storing computed Merkle roots.
    Each root represents a batch of request hashes for cryptographic verification.
    """
    __tablename__ = "merkle_roots"

    id = Column(Integer, primary_key=True, index=True)
    merkle_root = Column(String(64), nullable=False, index=True)  # SHA-256 hash (64 hex chars)
    start_time = Column(DateTime(timezone=True), nullable=False)
    end_time = Column(DateTime(timezone=True), nullable=False)
    request_count = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Blockchain anchoring fields
    is_anchored = Column(Boolean, default=False, nullable=False)
    tx_hash = Column(String(66), nullable=True)  # 0x + 64 hex chars
    block_number = Column(Integer, nullable=True)
    anchored_at = Column(DateTime(timezone=True), nullable=True)

