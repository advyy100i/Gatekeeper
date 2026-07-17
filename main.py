"""
Main entry point for the gaas-gateway FastAPI application.
"""

# Load environment variables FIRST
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional, Dict, List
from app.database import init_db, get_db
from app.models import User, Service, UsageLog, ApiKey, BotDetectionLog, ServiceConfig, RequestHash, MerkleRoot, AnomalyScoreLog
from app.bot_detector import calculate_bot_score, classify_traffic, should_block
from app.anomaly import gateway_hook as anomaly_gateway
from app.anomaly import config as anomaly_cfg
from app.anomaly.features import FeatureEvent
from app.anomaly.risk_engine import ACTION_TARPIT as ANOMALY_TARPIT, ACTION_BLOCK as ANOMALY_BLOCK
import httpx
import secrets
import time
from collections import defaultdict
import asyncio
from datetime import datetime, timedelta, timezone
import logging
import base64
import json
import re
import uuid
import hashlib
import os

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


# ============================================================================
# Watermarking Utilities
# ============================================================================

def generate_watermark(service_id: int, api_key_id: int, request_id: str, timestamp: str) -> str:
    """
    Generate a base64-encoded watermark containing tracing information.
    Format: service_id|api_key_id|request_id|timestamp
    """
    watermark_data = f"{service_id}|{api_key_id}|{request_id}|{timestamp}"
    encoded = base64.b64encode(watermark_data.encode()).decode()
    return encoded


def decode_watermark(encoded_watermark: str) -> Optional[Dict]:
    """
    Decode a base64-encoded watermark and extract metadata.
    Returns dict with service_id, api_key_id, request_id, timestamp or None if invalid.
    """
    try:
        decoded = base64.b64decode(encoded_watermark.encode()).decode()
        parts = decoded.split("|")
        if len(parts) != 4:
            return None
        return {
            "service_id": int(parts[0]),
            "api_key_id": int(parts[1]),
            "request_id": parts[2],
            "timestamp": parts[3]
        }
    except Exception:
        return None


def extract_watermark_from_json(data: dict) -> Optional[str]:
    """
    Extract _gaas_watermark field from JSON data (recursively).
    """
    if isinstance(data, dict):
        if "_gaas_watermark" in data:
            return data["_gaas_watermark"]
        for value in data.values():
            result = extract_watermark_from_json(value)
            if result:
                return result
    elif isinstance(data, list):
        for item in data:
            result = extract_watermark_from_json(item)
            if result:
                return result
    return None


def extract_watermark_from_text(text: str) -> Optional[str]:
    """
    Extract watermark from text content (hidden in HTML comment or suffix).
    Looks for pattern: <!-- GAAS_WM:base64_data --> or [GAAS_WM:base64_data]
    """
    # HTML comment pattern
    html_pattern = r'<!--\s*GAAS_WM:([A-Za-z0-9+/=]+)\s*-->'
    match = re.search(html_pattern, text)
    if match:
        return match.group(1)
    
    # Bracket pattern for plain text
    bracket_pattern = r'\[GAAS_WM:([A-Za-z0-9+/=]+)\]'
    match = re.search(bracket_pattern, text)
    if match:
        return match.group(1)
    
    return None


def inject_watermark_json(data, watermark: str):
    """
    Inject watermark into JSON data by adding _gaas_watermark field.
    If data is a dict, adds the field directly.
    If data is a list/array, wraps it in a dict with data and watermark.
    """
    if isinstance(data, dict):
        data["_gaas_watermark"] = watermark
        return data
    elif isinstance(data, list):
        # For arrays, wrap in an object with the data and watermark
        return {
            "data": data,
            "_gaas_watermark": watermark
        }
    else:
        # For other types (shouldn't happen with valid JSON), return as-is
        return data


def inject_watermark_text(text: str, watermark: str, content_type: str) -> str:
    """
    Inject watermark into text content.
    For HTML: adds as HTML comment at the end
    For plain text: adds as bracket-enclosed suffix
    """
    if "html" in content_type.lower():
        return f"{text}\n<!-- GAAS_WM:{watermark} -->"
    else:
        return f"{text}\n[GAAS_WM:{watermark}]"


# ============================================================================
# Merkle Tree / Cryptographic Transparency
# ============================================================================

# Merkle batch size: number of hashes to accumulate before computing a root
MERKLE_BATCH_SIZE = int(os.getenv("MERKLE_BATCH_SIZE", "10"))


def compute_request_hash(
    service_id: int,
    api_key_id: int,
    timestamp: datetime,
    request_path: str,
    response_status: int
) -> str:
    """
    Compute SHA-256 hash of API request for cryptographic transparency.
    
    Hash input format: service_id|api_key_id|timestamp_iso|request_path|response_status
    
    Args:
        service_id: ID of the service
        api_key_id: ID of the API key used
        timestamp: Request timestamp
        request_path: Request path (e.g., "/api/users")
        response_status: HTTP response status code
    
    Returns:
        64-character hexadecimal SHA-256 hash
    """
    # Format: service_id|api_key_id|timestamp_iso|request_path|response_status
    data = f"{service_id}|{api_key_id}|{timestamp.isoformat()}|{request_path}|{response_status}"
    return hashlib.sha256(data.encode()).hexdigest()


def build_merkle_tree(hashes: List[str]) -> str:
    """
    Build Merkle tree from list of hashes and return root hash.
    
    Uses binary Merkle tree construction:
    - Leaf nodes: Individual hashes
    - Parent nodes: SHA-256(left_hash + right_hash)
    - Odd number handling: Duplicate last hash
    
    Args:
        hashes: List of SHA-256 hashes (hex strings)
    
    Returns:
        Root hash of the Merkle tree (64-character hex string)
        Empty string if input is empty
    """
    if len(hashes) == 0:
        return ""
    if len(hashes) == 1:
        return hashes[0]
    
    # Build tree level by level
    current_level = hashes[:]
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            # If odd number, duplicate last hash
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            # Combine and hash
            parent = hashlib.sha256((left + right).encode()).hexdigest()
            next_level.append(parent)
        current_level = next_level
    
    return current_level[0]


def compute_and_store_merkle_root(db: Session) -> Optional[int]:
    """
    Compute Merkle root for unbatched request hashes and store it.
    
    Fetches the last MERKLE_BATCH_SIZE unbatched hashes, computes the Merkle root,
    stores it in merkle_roots table, and updates the hashes with the batch ID.
    
    Args:
        db: Database session
    
    Returns:
        ID of the created MerkleRoot record, or None if no unbatched hashes
    """
    # Fetch unbatched hashes (oldest first)
    unbatched_hashes = db.query(RequestHash).filter(
        RequestHash.merkle_batch_id == None
    ).order_by(RequestHash.timestamp.asc()).limit(MERKLE_BATCH_SIZE).all()
    
    if len(unbatched_hashes) < MERKLE_BATCH_SIZE:
        # Not enough hashes to create a batch yet
        return None
    
    # Extract hash values
    hash_values = [h.hash for h in unbatched_hashes]
    
    # Compute Merkle root
    merkle_root = build_merkle_tree(hash_values)
    
    # Get time range
    start_time = unbatched_hashes[0].timestamp
    end_time = unbatched_hashes[-1].timestamp
    
    # Create MerkleRoot record
    merkle_root_record = MerkleRoot(
        merkle_root=merkle_root,
        start_time=start_time,
        end_time=end_time,
        request_count=len(unbatched_hashes)
    )
    db.add(merkle_root_record)
    db.flush()  # Get the ID without committing
    
    # Update hashes with batch ID
    for hash_record in unbatched_hashes:
        hash_record.merkle_batch_id = merkle_root_record.id
    
    db.commit()
    db.refresh(merkle_root_record)
    
    logger.info(f"Computed Merkle root: batch_id={merkle_root_record.id}, root={merkle_root[:16]}..., count={len(unbatched_hashes)}")
    
    # Anchor to blockchain (async, non-blocking)
    try:
        from app.blockchain import blockchain_anchor
        
        result = blockchain_anchor.anchor_merkle_root(
            merkle_root=merkle_root,
            batch_id=merkle_root_record.id,
            request_count=len(unbatched_hashes)
        )
        
        if result:
            merkle_root_record.is_anchored = True
            merkle_root_record.tx_hash = result["tx_hash"]
            merkle_root_record.block_number = result["block_number"]
            merkle_root_record.anchored_at = datetime.now(timezone.utc)
            db.commit()
            logger.info(f"✅ Blockchain anchoring successful: tx={result['tx_hash']}")
        else:
            logger.info("Blockchain anchoring skipped or failed (non-blocking)")
    except Exception as e:
        logger.error(f"❌ Blockchain anchoring failed: {e}")
        # Don't fail Merkle computation if anchoring fails
        pass
    
    return merkle_root_record.id


app = FastAPI(
    title="GaaS Gateway",
    description="Gateway API for GaaS (Gateway as a Service)",
    version="1.0.0"
)

# Configure CORS. Origins come from CORS_ALLOW_ORIGINS (comma-separated) so the
# deployed frontend (e.g. a Vercel URL) can be allowed in production; defaults to
# the local dev frontend.
_cors_origins = [
    o.strip() for o in os.getenv(
        "CORS_ALLOW_ORIGINS", "http://localhost:3000"
    ).split(",") if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Initialize the database and, when embedded, the anomaly scoring worker."""
    init_db()

    # On hosting tiers without a separate background-worker process (e.g. Render
    # free), run the anomaly scorer in-process as a daemon thread by setting
    # AEGIS_EMBED_WORKER=1. In a full deployment the worker runs as its own
    # service instead (see render.yaml) and this stays disabled.
    if os.getenv("AEGIS_EMBED_WORKER", "").lower() in ("1", "true", "yes"):
        import threading
        from app.anomaly.worker import run_worker

        def _run():
            try:
                run_worker()
            except Exception as exc:  # never take down the gateway
                logger.error(f"embedded anomaly worker stopped: {exc}")

        threading.Thread(target=_run, name="anomaly-worker", daemon=True).start()
        logger.info("embedded anomaly worker thread started")


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Welcome to GaaS Gateway API"}


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/overview")
async def get_overview(db: Session = Depends(get_db)):
    """
    Get overview statistics for the gateway.
    
    Returns:
    - total_services: Total number of registered services
    - requests_today: Total requests made today
    - top_services: List of top services with request counts
    - average_rate_limit_usage: Average rate limit usage percentage
    - gateway_status: Current gateway operational status
    """
    # Get total services
    total_services = db.query(func.count(Service.id)).scalar() or 0
    
    # Get requests today (start of today to now)
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    requests_today = db.query(func.count(UsageLog.id)).filter(
        UsageLog.timestamp >= today_start
    ).scalar() or 0
    
    # Get top services (service name + request count)
    # Join Service with UsageLog, group by service, count requests, order by count DESC, limit to top 5
    top_services_query = db.query(
        Service.name,
        func.count(UsageLog.id).label('request_count')
    ).join(
        UsageLog, Service.id == UsageLog.service_id
    ).group_by(
        Service.id, Service.name
    ).order_by(
        func.count(UsageLog.id).desc()
    ).limit(5).all()
    
    top_services = [
        {"name": name, "request_count": count}
        for name, count in top_services_query
    ]
    
    # Calculate average rate limit usage
    # Rate limit: 10 requests per 60 seconds per API key
    # For each unique API key, calculate requests in last 60 seconds, then average the percentages
    sixty_seconds_ago = datetime.now(timezone.utc) - timedelta(seconds=60)
    
    # Get unique API keys
    unique_api_keys = db.query(UsageLog.api_key).distinct().all()
    unique_api_keys = [key[0] for key in unique_api_keys]
    
    if unique_api_keys:
        usage_percentages = []
        for api_key in unique_api_keys:
            # Count requests in last 60 seconds for this API key
            recent_requests = db.query(func.count(UsageLog.id)).filter(
                UsageLog.api_key == api_key,
                UsageLog.timestamp >= sixty_seconds_ago
            ).scalar() or 0
            
            # Calculate percentage (requests / limit * 100)
            usage_percentage = min((recent_requests / RATE_LIMIT_CAPACITY) * 100, 100.0)
            usage_percentages.append(usage_percentage)
        
        # Average the percentages
        average_rate_limit_usage = sum(usage_percentages) / len(usage_percentages) if usage_percentages else 0.0
    else:
        average_rate_limit_usage = 0.0
    
    # Gateway status
    gateway_status = "Operational"
    
    return {
        "total_services": total_services,
        "requests_today": requests_today,
        "top_services": top_services,
        "average_rate_limit_usage": round(average_rate_limit_usage, 2),
        "gateway_status": gateway_status
    }


class RegisterApiRequest(BaseModel):
    """Request model for registering a new API service."""
    name: str
    target_url: HttpUrl


class RegisterApiResponse(BaseModel):
    """Response model for API registration."""
    service_id: int
    gateway_url: str
    api_key: Optional[str] = None  # Only returned once during user creation


class CreateApiKeyResponse(BaseModel):
    """Response model for API key creation."""
    api_key: str
    service_id: int
    message: str = "API key created successfully. Save this key securely - it will only be shown once."


class UpdateRateLimitRequest(BaseModel):
    """Request model for updating API key rate limits."""
    requests: int
    window_seconds: int


def get_current_user(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db)
) -> User:
    """
    Dependency to validate API key from X-API-Key header.
    First checks ApiKey table for active keys, then falls back to User.api_key for backward compatibility.
    Returns the authenticated user or raises HTTP 401.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing X-API-Key header"
        )
    
    # First, check ApiKey table for active keys (new system)
    api_key_obj = db.query(ApiKey).filter(
        ApiKey.key == x_api_key,
        ApiKey.is_active == True
    ).first()
    
    if api_key_obj:
        # API key found in ApiKey table, get the user from the service owner
        service = db.query(Service).filter(Service.id == api_key_obj.service_id).first()
        if service:
            user = db.query(User).filter(User.id == service.owner_id).first()
            if user:
                return user
    
    # Fallback to User.api_key for backward compatibility (old system)
    user = db.query(User).filter(User.api_key == x_api_key).first()
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    
    return user


# Rate limiting using Token Bucket algorithm
# In-memory store for rate limit data (per API key)
# In production, this would be replaced with Redis for distributed rate limiting
_rate_limit_store = defaultdict(lambda: {'tokens': 10, 'last_refill': time.time()})
_rate_limit_lock = asyncio.Lock()

# Rate limit configuration: 10 requests per 60 seconds
RATE_LIMIT_CAPACITY = 10
RATE_LIMIT_REFILL_RATE = 10.0 / 60.0  # tokens per second (10 tokens per 60 seconds)
RATE_LIMIT_WINDOW = 60.0  # seconds


async def check_rate_limit(api_key: str, db: Session) -> bool:
    """
    Check if the API key has available tokens using Token Bucket algorithm.
    
    Checks for per-API-key rate limit overrides (rate_limit_requests, rate_limit_window_seconds).
    If present, uses those values. Otherwise, falls back to service-level defaults.
    
    Returns True if request is allowed, False if rate limit exceeded.
    """
    # Determine rate limit configuration (check for API key overrides)
    capacity = RATE_LIMIT_CAPACITY
    refill_rate = RATE_LIMIT_REFILL_RATE
    window = RATE_LIMIT_WINDOW
    
    # Check if this API key has custom rate limits
    api_key_obj = db.query(ApiKey).filter(
        ApiKey.key == api_key,
        ApiKey.is_active == True
    ).first()
    
    if api_key_obj and api_key_obj.rate_limit_requests is not None and api_key_obj.rate_limit_window_seconds is not None:
        # Use API key-specific rate limits
        capacity = api_key_obj.rate_limit_requests
        window = float(api_key_obj.rate_limit_window_seconds)
        refill_rate = float(capacity) / window  # tokens per second
    # Otherwise, use defaults (RATE_LIMIT_CAPACITY, RATE_LIMIT_WINDOW, RATE_LIMIT_REFILL_RATE)
    
    async with _rate_limit_lock:
        now = time.time()
        # Use a unique key that includes rate limit config to separate buckets with different limits
        bucket_key = f"{api_key}:{capacity}:{window}"
        bucket = _rate_limit_store[bucket_key]
        
        # Initialize bucket if it doesn't exist or capacity changed
        if 'capacity' not in bucket or bucket['capacity'] != capacity:
            bucket['tokens'] = float(capacity)
            bucket['last_refill'] = now
            bucket['capacity'] = capacity
            bucket['refill_rate'] = refill_rate
        
        # Calculate elapsed time since last refill
        elapsed = now - bucket['last_refill']
        
        # Refill tokens based on elapsed time (but don't exceed capacity)
        tokens_to_add = elapsed * bucket['refill_rate']
        bucket['tokens'] = min(float(capacity), bucket['tokens'] + tokens_to_add)
        bucket['last_refill'] = now
        
        # Check if we have tokens available
        if bucket['tokens'] >= 1.0:
            # Consume one token
            bucket['tokens'] -= 1.0
            return True
        else:
            # Rate limit exceeded
            return False


def validate_api_key_for_service(api_key: str, service_id: int, db: Session) -> bool:
    """
    Validate that an API key is authorized to access a specific service.
    
    Checks:
    1. API key exists and is active in the ApiKey table
    2. API key belongs to the specified service (service_id matches)
    3. Service belongs to the same owner as the API key's service (for additional security)
    
    Args:
        api_key: The API key string to validate
        service_id: The service ID being accessed
        db: Database session
    
    Returns:
        True if authorized, False otherwise
    """
    # Check if API key exists and is active
    api_key_obj = db.query(ApiKey).filter(
        ApiKey.key == api_key,
        ApiKey.is_active == True
    ).first()
    
    if not api_key_obj:
        # Try fallback to User.api_key for backward compatibility
        user = db.query(User).filter(User.api_key == api_key).first()
        if user:
            # For user-level API keys, check if the service belongs to this user
            service = db.query(Service).filter(Service.id == service_id).first()
            if service and service.owner_id == user.id:
                return True
        return False
    
    # Check if the API key belongs to the requested service
    if api_key_obj.service_id != service_id:
        logger.warning(
            f"Authorization failed: API key (service_id={api_key_obj.service_id}) "
            f"attempted to access service_id={service_id}"
        )
        return False
    
    return True


@app.post("/register-api", response_model=RegisterApiResponse)
async def register_api(
    request: RegisterApiRequest,
    db: Session = Depends(get_db)
):
    """
    Register a new API service.
    
    Creates a new Service entry linked to an existing user.
    If no user exists, auto-creates a default user.
    Returns service_id, gateway_url, and api_key (only on first user creation).
    """
    # Get or create a default user
    user = db.query(User).first()
    api_key_to_return = None
    
    if not user:
        # Create a default user with a generated API key
        api_key = secrets.token_urlsafe(32)
        user = User(
            name="Default User",
            api_key=api_key
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        # Return API key only once during creation
        api_key_to_return = api_key
    
    # Create a new service
    service = Service(
        name=request.name,
        target_url=str(request.target_url),
        owner_id=user.id
    )
    db.add(service)
    db.commit()
    db.refresh(service)
    
    # Return the response
    return RegisterApiResponse(
        service_id=service.id,
        gateway_url=f"/proxy/{service.id}",
        api_key=api_key_to_return
    )


async def proxy_request(
    service: Service,
    request: Request,
    method: str,
    api_key: str,
    db: Session,
    path_suffix: str = ""
) -> Response:
    """
    Proxy an HTTP request to the service's target_url.
    
    Forwards query parameters, request body, HTTP method, and safe headers.
    Returns status code, response body, and response headers.
    Handles timeouts gracefully.
    Injects watermarks if enabled for the service.
    
    Args:
        path_suffix: Optional path to append to the target URL
    """
    # Validate and normalize the target URL
    target_url = service.target_url.strip()
    if not target_url:
        raise HTTPException(
            status_code=500,
            detail="Service target_url is not configured"
        )
    
    # Ensure URL has a scheme
    if not target_url.startswith(('http://', 'https://')):
        raise HTTPException(
            status_code=500,
            detail=f"Invalid target_url format: {target_url}. URL must start with http:// or https://"
        )
    
    # Append path suffix if provided
    if path_suffix:
        # Remove trailing slash from target_url and leading slash from path_suffix
        target_url = target_url.rstrip('/')
        path_suffix = path_suffix.lstrip('/')
        target_url = f"{target_url}/{path_suffix}"
    
    # Look up the API key object once (used by anomaly scoring, watermarking, hashing)
    api_key_obj = db.query(ApiKey).filter(
        ApiKey.key == api_key,
        ApiKey.is_active == True
    ).first()

    # ------------------------------------------------------------------
    # Adaptive anomaly enforcement (Feature A)
    # Reads the async ML worker's cached risk decision — one Redis GET,
    # fail-open. Static controls (auth, rate limit) have already run.
    # ------------------------------------------------------------------
    if api_key_obj:
        anomaly_action, anomaly_risk = await anomaly_gateway.get_decision(api_key_obj.id)
        if anomaly_action == ANOMALY_BLOCK:
            logger.warning(
                f"Anomaly BLOCK: api_key_id={api_key_obj.id} risk={anomaly_risk:.3f}"
            )
            raise HTTPException(
                status_code=403,
                detail="Request blocked by adaptive security (anomalous behavior detected)"
            )
        elif anomaly_action == ANOMALY_TARPIT:
            logger.info(
                f"Anomaly TARPIT: api_key_id={api_key_obj.id} risk={anomaly_risk:.3f} "
                f"delay={anomaly_cfg.TARPIT_SECONDS}s"
            )
            await asyncio.sleep(anomaly_cfg.TARPIT_SECONDS)

    # Get safe headers (exclude host, content-length, and X-API-Key)
    excluded_headers = {'host', 'content-length', 'x-api-key', 'connection', 'transfer-encoding'}
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in excluded_headers
    }
    
    # Get query parameters
    query_params = dict(request.query_params)
    
    # Get request body if present (for methods that may have body)
    body = None
    if method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        try:
            body = await request.body()
            # Only use body if it's not empty
            if not body:
                body = None
        except Exception:
            body = None
    
    # Make the proxied request with timeout
    timeout = httpx.Timeout(30.0, connect=10.0)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.request(
                method=method,
                url=target_url,
                params=query_params,
                content=body,
                headers=headers,
                follow_redirects=True
            )
            
            # Build response headers (exclude some that shouldn't be forwarded)
            # Note: httpx automatically decodes gzip/deflate, so we must not forward content-encoding
            response_headers = {
                key: value
                for key, value in response.headers.items()
                if key.lower() not in {'content-length', 'connection', 'transfer-encoding', 'content-encoding'}
            }
            
            # api_key_obj was fetched once at the top of proxy_request

            # ------------------------------------------------------------------
            # Publish feature event for async anomaly scoring (metadata only,
            # never bodies). Fire-and-forget: scoring stays off the hot path.
            # ------------------------------------------------------------------
            if api_key_obj:
                try:
                    event = FeatureEvent(
                        api_key_id=api_key_obj.id,
                        service_id=service.id,
                        ts=time.time(),
                        method=method,
                        path=str(request.url.path),
                        status=response.status_code,
                        payload_size=len(response.content or b""),
                    )
                    asyncio.create_task(anomaly_gateway.publish_event(event))
                except Exception as e:
                    logger.debug(f"anomaly event publish skipped: {e}")

            # Store request hash for cryptographic transparency
            if api_key_obj:
                try:
                    # Extract request path from the original request
                    request_path = str(request.url.path)
                    
                    # Compute hash
                    request_timestamp = datetime.now(timezone.utc)
                    request_hash = compute_request_hash(
                        service_id=service.id,
                        api_key_id=api_key_obj.id,
                        timestamp=request_timestamp,
                        request_path=request_path,
                        response_status=response.status_code
                    )
                    
                    # Store hash
                    hash_record = RequestHash(
                        service_id=service.id,
                        api_key_id=api_key_obj.id,
                        timestamp=request_timestamp,
                        request_path=request_path,
                        response_status=response.status_code,
                        hash=request_hash,
                        merkle_batch_id=None  # Will be set when batched
                    )
                    db.add(hash_record)
                    db.commit()
                    
                    logger.debug(f"Stored request hash: service_id={service.id}, hash={request_hash[:16]}...")
                    
                    # Try to compute Merkle root if we have enough unbatched hashes
                    try:
                        compute_and_store_merkle_root(db)
                    except Exception as e:
                        logger.warning(f"Failed to compute Merkle root: {e}")
                        # Don't fail the request if Merkle computation fails
                        pass
                except Exception as e:
                    logger.warning(f"Failed to store request hash: {e}")
                    # Don't fail the request if hash storage fails
                    db.rollback()
                    pass
            
            # Log successful requests (HTTP 2xx) to UsageLog and update billing
            if 200 <= response.status_code < 300:
                try:
                    # Log usage
                    usage_log = UsageLog(
                        service_id=service.id,
                        api_key=api_key
                        # timestamp will be set automatically via server_default
                    )
                    db.add(usage_log)
                    
                    # Update billing: increment ApiKey.total_cost by ApiKey.price_per_request
                    if api_key_obj:
                        api_key_obj.total_cost += api_key_obj.price_per_request
                    
                    db.commit()
                except Exception:
                    # Don't fail the request if logging/billing update fails
                    db.rollback()
                    pass
            
            # Prepare response content (potentially with watermark)
            response_content = response.content
            content_type = response.headers.get('content-type', '')
            
            # Inject watermark if enabled for service
            if getattr(service, 'watermarking_enabled', False) and api_key_obj:
                try:
                    # Generate unique request ID and timestamp
                    request_id = str(uuid.uuid4())[:8]
                    timestamp = datetime.now(timezone.utc).isoformat()
                    
                    # Generate watermark
                    watermark = generate_watermark(
                        service_id=service.id,
                        api_key_id=api_key_obj.id,
                        request_id=request_id,
                        timestamp=timestamp
                    )
                    
                    # Inject based on content type
                    if 'application/json' in content_type:
                        try:
                            json_data = json.loads(response_content.decode('utf-8'))
                            watermarked_data = inject_watermark_json(json_data, watermark)
                            response_content = json.dumps(watermarked_data).encode('utf-8')
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            # If JSON parsing fails, treat as text
                            text_content = response_content.decode('utf-8', errors='replace')
                            watermarked_text = inject_watermark_text(text_content, watermark, content_type)
                            response_content = watermarked_text.encode('utf-8')
                    elif 'text/' in content_type or 'html' in content_type:
                        text_content = response_content.decode('utf-8', errors='replace')
                        watermarked_text = inject_watermark_text(text_content, watermark, content_type)
                        response_content = watermarked_text.encode('utf-8')
                    # For binary content types (images, etc.), don't add watermark
                except Exception as e:
                    # Don't fail the request if watermarking fails
                    logger.warning(f"Watermarking failed: {e}")
                    pass
            
            # Return response with status code, body, and headers
            return Response(
                content=response_content,
                status_code=response.status_code,
                headers=response_headers,
                media_type=response.headers.get('content-type')
            )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="Gateway timeout: The target service did not respond in time"
        )
    except httpx.ConnectError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Bad gateway: Cannot connect to target service. The hostname may be invalid or unreachable. Error: {str(e)}"
        )
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Bad gateway: Failed to connect to target service - {str(e)}"
        )


@app.get("/proxy/{service_id}")
@app.get("/proxy/{service_id}/{path:path}")
async def proxy_get(
    service_id: int,
    request: Request,
    path: str = "",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Proxy endpoint for GET requests.
    Protected by API key authentication and rate limiting.
    """
    # Extract API key from request header for rate limiting
    api_key_from_header = request.headers.get("X-API-Key", "")
    
    # Verify service exists
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Validate API key is authorized for this service
    if not validate_api_key_for_service(api_key_from_header, service_id, db):
        raise HTTPException(
            status_code=403,
            detail="API key not authorized for this service"
        )
    
    # Bot detection
    bot_score = calculate_bot_score(request, api_key_from_header, db)
    classification = classify_traffic(bot_score)
    
    # Get service configuration for bot blocking
    service_config = db.query(ServiceConfig).filter(
        ServiceConfig.service_id == service_id
    ).first()
    
    block_enabled = service_config.block_bots_enabled if service_config else False
    
    # Determine if request should be blocked
    should_block_request, action_taken = should_block(bot_score, block_enabled)
    
    # Log bot detection
    try:
        bot_log = BotDetectionLog(
            service_id=service_id,
            api_key=api_key_from_header,
            bot_score=bot_score,
            classification=classification,
            user_agent=request.headers.get('user-agent', ''),
            action_taken=action_taken
        )
        db.add(bot_log)
        db.commit()
    except Exception:
        db.rollback()
        pass  # Don't fail request if logging fails
    
    # Block if necessary
    if should_block_request:
        raise HTTPException(
            status_code=403,
            detail=f"Bot traffic detected (score: {bot_score:.2f}). This service has bot blocking enabled."
        )
    
    # Check rate limit using the API key from header
    if not await check_rate_limit(api_key_from_header, db):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded"
        )
    
    return await proxy_request(service, request, "GET", api_key_from_header, db, path)


@app.post("/proxy/{service_id}")
@app.post("/proxy/{service_id}/{path:path}")
async def proxy_post(
    service_id: int,
    request: Request,
    path: str = "",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Proxy endpoint for POST requests.
    Protected by API key authentication and rate limiting.
    """
    api_key_from_header = request.headers.get("X-API-Key", "")
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Validate API key is authorized for this service
    if not validate_api_key_for_service(api_key_from_header, service_id, db):
        raise HTTPException(
            status_code=403,
            detail="API key not authorized for this service"
        )
    
    # Bot detection
    bot_score = calculate_bot_score(request, api_key_from_header, db)
    classification = classify_traffic(bot_score)
    service_config = db.query(ServiceConfig).filter(ServiceConfig.service_id == service_id).first()
    block_enabled = service_config.block_bots_enabled if service_config else False
    should_block_request, action_taken = should_block(bot_score, block_enabled)
    
    try:
        bot_log = BotDetectionLog(
            service_id=service_id, api_key=api_key_from_header, bot_score=bot_score,
            classification=classification, user_agent=request.headers.get('user-agent', ''),
            action_taken=action_taken
        )
        db.add(bot_log)
        db.commit()
    except Exception:
        db.rollback()
    
    if should_block_request:
        raise HTTPException(status_code=403, detail=f"Bot traffic detected (score: {bot_score:.2f}). This service has bot blocking enabled.")
    
    if not await check_rate_limit(api_key_from_header, db):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    return await proxy_request(service, request, "POST", api_key_from_header, db, path)


@app.put("/proxy/{service_id}")
@app.put("/proxy/{service_id}/{path:path}")
async def proxy_put(
    service_id: int,
    request: Request,
    path: str = "",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Proxy endpoint for PUT requests.
    Protected by API key authentication and rate limiting.
    """
    api_key_from_header = request.headers.get("X-API-Key", "")
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Validate API key is authorized for this service
    if not validate_api_key_for_service(api_key_from_header, service_id, db):
        raise HTTPException(
            status_code=403,
            detail="API key not authorized for this service"
        )
    
    # Bot detection
    bot_score = calculate_bot_score(request, api_key_from_header, db)
    classification = classify_traffic(bot_score)
    service_config = db.query(ServiceConfig).filter(ServiceConfig.service_id == service_id).first()
    block_enabled = service_config.block_bots_enabled if service_config else False
    should_block_request, action_taken = should_block(bot_score, block_enabled)
    
    try:
        bot_log = BotDetectionLog(
            service_id=service_id, api_key=api_key_from_header, bot_score=bot_score,
            classification=classification, user_agent=request.headers.get('user-agent', ''),
            action_taken=action_taken
        )
        db.add(bot_log)
        db.commit()
    except Exception:
        db.rollback()
    
    if should_block_request:
        raise HTTPException(status_code=403, detail=f"Bot traffic detected (score: {bot_score:.2f}). This service has bot blocking enabled.")
    
    if not await check_rate_limit(api_key_from_header, db):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    return await proxy_request(service, request, "PUT", api_key_from_header, db, path)


@app.delete("/proxy/{service_id}")
@app.delete("/proxy/{service_id}/{path:path}")
async def proxy_delete(
    service_id: int,
    request: Request,
    path: str = "",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Proxy endpoint for DELETE requests.
    Protected by API key authentication and rate limiting.
    """
    api_key_from_header = request.headers.get("X-API-Key", "")
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Validate API key is authorized for this service
    if not validate_api_key_for_service(api_key_from_header, service_id, db):
        raise HTTPException(
            status_code=403,
            detail="API key not authorized for this service"
        )
    
    # Bot detection
    bot_score = calculate_bot_score(request, api_key_from_header, db)
    classification = classify_traffic(bot_score)
    service_config = db.query(ServiceConfig).filter(ServiceConfig.service_id == service_id).first()
    block_enabled = service_config.block_bots_enabled if service_config else False
    should_block_request, action_taken = should_block(bot_score, block_enabled)
    
    try:
        bot_log = BotDetectionLog(
            service_id=service_id, api_key=api_key_from_header, bot_score=bot_score,
            classification=classification, user_agent=request.headers.get('user-agent', ''),
            action_taken=action_taken
        )
        db.add(bot_log)
        db.commit()
    except Exception:
        db.rollback()
    
    if should_block_request:
        raise HTTPException(status_code=403, detail=f"Bot traffic detected (score: {bot_score:.2f}). This service has bot blocking enabled.")
    
    if not await check_rate_limit(api_key_from_header, db):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    return await proxy_request(service, request, "DELETE", api_key_from_header, db, path)


@app.get("/me/api-key")
async def get_my_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db)
):
    """
    Get the user's API key.
    
    This endpoint is for demo purposes only.
    Returns the API key only once. After first retrieval,
    marks it as revealed and subsequent calls return a message
    saying the key cannot be viewed again.
    
    For demo: If no API key is provided, returns the first user's
    API key if it hasn't been revealed yet.
    """
    # If API key is provided, authenticate and get that user
    if x_api_key:
        user = db.query(User).filter(User.api_key == x_api_key).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid API key")
    else:
        # For demo: get the first user if no auth provided
        user = db.query(User).first()
        if not user:
            raise HTTPException(
                status_code=404,
                detail="No user found. Please register an API first using POST /register-api"
            )
    
    # Refresh user to ensure we have the latest data
    db.refresh(user)
    
    # Check if API key has already been revealed (handle None as False)
    if user.api_key_revealed is True:
        return {
            "message": "API key cannot be viewed again. It was already revealed once."
        }
    
    # Mark as revealed and return the API key
    user.api_key_revealed = True
    db.commit()
    db.refresh(user)
    
    return {
        "api_key": user.api_key
    }


@app.get("/usage/{service_id}")
async def get_usage_stats(
    service_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get usage statistics for a service.
    
    Returns total request count and request count grouped by API key.
    Protected by API key authentication.
    """
    # Verify service exists
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Get total request count for this service
    total_count = db.query(func.count(UsageLog.id)).filter(
        UsageLog.service_id == service_id
    ).scalar()
    
    # Get request count grouped by API key
    usage_by_api_key = db.query(
        UsageLog.api_key,
        func.count(UsageLog.id).label('count')
    ).filter(
        UsageLog.service_id == service_id
    ).group_by(UsageLog.api_key).all()
    
    # Format the grouped results
    api_key_counts = [
        {"api_key": api_key, "count": count}
        for api_key, count in usage_by_api_key
    ]
    
    return {
        "service_id": service_id,
        "total_requests": total_count or 0,
        "requests_by_api_key": api_key_counts
    }


@app.post("/services/{service_id}/keys", response_model=CreateApiKeyResponse)
async def create_service_api_key(
    service_id: int,
    db: Session = Depends(get_db)
):
    """
    Create a new API key for a service.
    
    Generates a new API key, stores it as active in the ApiKey table,
    and returns it once. Existing keys remain valid and are not revoked.
    
    Control-plane endpoint - no authentication required.
    """
    # Verify service exists
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Generate a unique API key
    # Keep generating until we get a unique one (should be rare collision)
    max_attempts = 10
    for attempt in range(max_attempts):
        new_api_key = secrets.token_urlsafe(32)
        
        # Check if key already exists (both in ApiKey table and User table for uniqueness)
        existing_api_key = db.query(ApiKey).filter(ApiKey.key == new_api_key).first()
        existing_user_key = db.query(User).filter(User.api_key == new_api_key).first()
        
        if not existing_api_key and not existing_user_key:
            break
        
        if attempt == max_attempts - 1:
            raise HTTPException(
                status_code=500,
                detail="Failed to generate unique API key. Please try again."
            )
    
    # Create new ApiKey entry
    api_key_obj = ApiKey(
        key=new_api_key,
        service_id=service_id,
        is_active=True
    )
    
    db.add(api_key_obj)
    db.commit()
    db.refresh(api_key_obj)
    
    return CreateApiKeyResponse(
        api_key=new_api_key,
        service_id=service_id
    )


@app.get("/api-keys")
async def list_all_api_keys(
    db: Session = Depends(get_db)
):
    """
    List all services and their API keys.
    
    Control-plane endpoint - no authentication required.
    Returns all services with their API keys.
    """
    # Get all services (control-plane endpoint - public access)
    services = db.query(Service).all()
    
    result = []
    for service in services:
        # Get all API keys for this service
        api_keys = db.query(ApiKey).filter(ApiKey.service_id == service.id).order_by(ApiKey.created_at.desc()).all()
        
        result.append({
            "service_id": service.id,
            "service_name": service.name,
            "api_keys": [
                {
                    "id": key.id,
                    "key_masked": f"{key.key[:8]}••••{key.key[-4:]}" if len(key.key) > 12 else "••••••••",
                    "created_at": key.created_at.isoformat() if key.created_at else None,
                    "is_active": key.is_active,
                    "rate_limit_requests": key.rate_limit_requests,
                    "rate_limit_window_seconds": key.rate_limit_window_seconds
                }
                for key in api_keys
            ]
        })
    
    return {"services": result}


@app.get("/services/{service_id}/keys")
async def list_service_api_keys(
    service_id: int,
    db: Session = Depends(get_db)
):
    """
    List all API keys for a service.
    
    Returns API keys with masked values, timestamps, and status.
    Control-plane endpoint - no authentication required.
    """
    # Verify service exists
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Get all API keys for this service
    api_keys = db.query(ApiKey).filter(ApiKey.service_id == service_id).order_by(ApiKey.created_at.desc()).all()
    
    return {
        "service_id": service_id,
        "service_name": service.name,
        "api_keys": [
            {
                "id": key.id,
                "key_masked": f"{key.key[:8]}••••{key.key[-4:]}" if len(key.key) > 12 else "••••••••",
                "created_at": key.created_at.isoformat() if key.created_at else None,
                "is_active": key.is_active,
                "rate_limit_requests": key.rate_limit_requests,
                "rate_limit_window_seconds": key.rate_limit_window_seconds
            }
            for key in api_keys
        ]
    }


@app.patch("/services/{service_id}/keys/{key_id}/revoke")
async def revoke_service_api_key(
    service_id: int,
    key_id: int,
    db: Session = Depends(get_db)
):
    """
    Revoke an API key for a service.
    
    Sets the API key's is_active to False, making it invalid for authentication.
    Control-plane endpoint - no authentication required.
    """
    # Verify service exists
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Get the API key
    api_key = db.query(ApiKey).filter(
        ApiKey.id == key_id,
        ApiKey.service_id == service_id
    ).first()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    # Revoke the key
    api_key.is_active = False
    db.commit()
    db.refresh(api_key)
    
    return {
        "message": "API key revoked successfully",
        "key_id": key_id,
        "service_id": service_id
    }


@app.put("/api-keys/{key_id}/rate-limit")
async def update_api_key_rate_limit(
    key_id: int,
    request: UpdateRateLimitRequest,
    db: Session = Depends(get_db)
):
    """
    Update rate limits for a specific API key.
    
    Sets rate_limit_requests and rate_limit_window_seconds on the ApiKey model.
    Changes take effect immediately for subsequent requests.
    Control-plane endpoint - no authentication required.
    """
    # Validate input
    if request.requests <= 0:
        raise HTTPException(status_code=400, detail="requests must be greater than 0")
    if request.window_seconds <= 0:
        raise HTTPException(status_code=400, detail="window_seconds must be greater than 0")
    
    # Get the API key
    api_key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    # Update rate limit settings
    api_key.rate_limit_requests = request.requests
    api_key.rate_limit_window_seconds = request.window_seconds
    
    db.commit()
    db.refresh(api_key)
    
    return {
        "message": "Rate limit updated successfully",
        "key_id": key_id,
        "rate_limit_requests": api_key.rate_limit_requests,
        "rate_limit_window_seconds": api_key.rate_limit_window_seconds
    }


class UpdatePricingRequest(BaseModel):
    """Request model for updating API key pricing."""
    price_per_request: float


@app.put("/api-keys/{key_id}/pricing")
async def update_api_key_pricing(
    key_id: int,
    request: UpdatePricingRequest,
    db: Session = Depends(get_db)
):
    """
    Update price_per_request for a specific API key.
    
    Updates the price per request for billing calculations.
    Control-plane endpoint - no authentication required.
    """
    print(f"PUT /api-keys/{key_id}/pricing endpoint hit with price_per_request={request.price_per_request}")
    logger.info(f"PUT /api-keys/{key_id}/pricing called with price_per_request={request.price_per_request}")
    
    # Validate price_per_request > 0
    if request.price_per_request <= 0:
        error_msg = f"Invalid price_per_request: {request.price_per_request} (must be > 0)"
        print(f"ERROR: {error_msg}")
        logger.warning(error_msg)
        raise HTTPException(
            status_code=400,
            detail="price_per_request must be greater than 0"
        )
    
    # Get the API key
    api_key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    
    if not api_key:
        error_msg = f"API key not found: key_id={key_id}"
        print(f"ERROR: {error_msg}")
        logger.warning(error_msg)
        raise HTTPException(status_code=404, detail="API key not found")
    
    # Update price_per_request
    old_price = api_key.price_per_request
    api_key.price_per_request = request.price_per_request
    
    db.commit()
    db.refresh(api_key)
    
    success_msg = f"Updated price_per_request for key_id={key_id}: {old_price} -> {api_key.price_per_request}"
    print(f"SUCCESS: {success_msg}")
    logger.info(success_msg)
    
    # Return updated ApiKey
    return {
        "id": api_key.id,
        "key": f"{api_key.key[:8]}••••{api_key.key[-4:]}" if len(api_key.key) > 12 else "••••••••",
        "service_id": api_key.service_id,
        "is_active": api_key.is_active,
        "created_at": api_key.created_at.isoformat() if api_key.created_at else None,
        "rate_limit_requests": api_key.rate_limit_requests,
        "rate_limit_window_seconds": api_key.rate_limit_window_seconds,
        "price_per_request": float(api_key.price_per_request),
        "total_cost": float(api_key.total_cost)
    }


@app.get("/billing/summary")
async def get_billing_summary(db: Session = Depends(get_db)):
    """
    Get billing summary overview.
    
    Returns aggregated billing metrics:
    - total_requests: Total number of requests across all API keys
    - total_cost: Total accumulated cost across all API keys
    - cost_this_month: Current billing cycle cost (same as total_cost for now)
    
    Control-plane endpoint - no authentication required.
    """
    # Get all API keys
    api_keys = db.query(ApiKey).all()
    
    total_requests = 0
    total_cost = 0.0
    
    for api_key in api_keys:
        # Count usage log entries for this API key
        requests_used = db.query(func.count(UsageLog.id)).filter(
            UsageLog.api_key == api_key.key
        ).scalar() or 0
        
        total_requests += requests_used
        total_cost += float(api_key.total_cost)
    
    # Cost this month is the same as total_cost for now (manual reset cycles)
    cost_this_month = total_cost
    
    return {
        "total_requests": total_requests,
        "total_cost": total_cost,
        "cost_this_month": cost_this_month
    }


@app.get("/billing/api-keys")
async def get_billing_api_keys(db: Session = Depends(get_db)):
    """
    Get billing information for all API keys.
    
    Returns billing data including requests used, price per request, and total cost.
    Control-plane endpoint - no authentication required.
    """
    # Query all API keys
    api_keys = db.query(ApiKey).all()
    
    result = []
    for api_key in api_keys:
        # Get service name
        service = db.query(Service).filter(Service.id == api_key.service_id).first()
        service_name = service.name if service else "Unknown"
        
        # Count usage log entries for this API key
        requests_used = db.query(func.count(UsageLog.id)).filter(
            UsageLog.api_key == api_key.key
        ).scalar() or 0
        
        result.append({
            "api_key_id": api_key.id,
            "service_name": service_name,
            "requests_used": requests_used,
            "price_per_request": float(api_key.price_per_request),
            "total_cost": float(api_key.total_cost)
        })
    
    return {"api_keys": result}


@app.put("/billing/api-keys/{key_id}/price")
async def update_api_key_price(
    key_id: int,
    request: dict,
    db: Session = Depends(get_db)
):
    """
    Update price_per_request for a specific API key.
    
    Control-plane endpoint - no authentication required.
    """
    price_per_request = request.get("price_per_request")
    
    if price_per_request is None:
        raise HTTPException(status_code=400, detail="price_per_request is required")
    
    # Validate price > 0
    try:
        price = float(price_per_request)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="price_per_request must be a valid number")
    
    if price <= 0:
        raise HTTPException(status_code=400, detail="price_per_request must be greater than 0")
    
    # Validate max 3 decimal places
    decimal_places = len(str(price).split('.')[-1]) if '.' in str(price) else 0
    if decimal_places > 3:
        raise HTTPException(status_code=400, detail="price_per_request must have at most 3 decimal places")
    
    # Get the API key
    api_key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    # Update price_per_request
    api_key.price_per_request = price
    
    db.commit()
    db.refresh(api_key)
    
    return {
        "message": "Price per request updated successfully",
        "key_id": key_id,
        "price_per_request": float(api_key.price_per_request)
    }


    return {
        "message": "Billing cycle reset successfully. All API key costs have been cleared.",
        "reset_count": len(api_keys)
    }


# ============================================================================
# Bot Detection & Security Endpoints
# ============================================================================

@app.get("/security/bot-activity")
async def get_bot_activity(db: Session = Depends(get_db)):
    """
    Get recent bot activity logs.
    """
    # Get total requests count
    total_requests = db.query(func.count(BotDetectionLog.id)).scalar() or 0
    
    # Get counts by classification
    bot_count = db.query(func.count(BotDetectionLog.id)).filter(
        BotDetectionLog.classification == "bot"
    ).scalar() or 0
    
    suspicious_count = db.query(func.count(BotDetectionLog.id)).filter(
        BotDetectionLog.classification == "suspicious"
    ).scalar() or 0
    
    blocked_count = db.query(func.count(BotDetectionLog.id)).filter(
        BotDetectionLog.action_taken == "blocked"
    ).scalar() or 0
    
    # Calculate bot percentage
    bot_percentage = (bot_count / total_requests * 100) if total_requests > 0 else 0
    
    # Get recent logs (last 50)
    recent_logs = db.query(BotDetectionLog).order_by(
        BotDetectionLog.timestamp.desc()
    ).limit(50).all()
    
    # Format logs
    formatted_logs = []
    for log in recent_logs:
        service = db.query(Service).filter(Service.id == log.service_id).first()
        service_name = service.name if service else "Unknown"
        
        formatted_logs.append({
            "id": log.id,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "service_id": log.service_id,
            "service_name": service_name,
            "api_key": f"{log.api_key[:8]}..." if len(log.api_key) > 8 else log.api_key,
            "bot_score": log.bot_score,
            "classification": log.classification,
            "user_agent": log.user_agent,
            "action_taken": log.action_taken
        })
    
    return {
        "total_requests": total_requests,
        "bot_percentage": round(bot_percentage, 1),
        "blocked_count": blocked_count,
        "suspicious_count": suspicious_count,
        "recent_activity": formatted_logs
    }


@app.get("/security/bot-stats")
async def get_bot_stats(db: Session = Depends(get_db)):
    """
    Get bot statistics breakdown.
    """
    # Classification breakdown
    human_count = db.query(func.count(BotDetectionLog.id)).filter(
        BotDetectionLog.classification == "human"
    ).scalar() or 0
    
    suspicious_count = db.query(func.count(BotDetectionLog.id)).filter(
        BotDetectionLog.classification == "suspicious"
    ).scalar() or 0
    
    bot_count = db.query(func.count(BotDetectionLog.id)).filter(
        BotDetectionLog.classification == "bot"
    ).scalar() or 0
    
    # Top bot user agents
    top_agents = db.query(
        BotDetectionLog.user_agent,
        func.count(BotDetectionLog.id).label('count')
    ).filter(
        BotDetectionLog.classification == "bot"
    ).group_by(
        BotDetectionLog.user_agent
    ).order_by(
        func.count(BotDetectionLog.id).desc()
    ).limit(5).all()
    
    formatted_agents = [
        {"user_agent": agent, "count": count}
        for agent, count in top_agents
    ]
    
    return {
        "classification_breakdown": {
            "human": human_count,
            "suspicious": suspicious_count,
            "bot": bot_count
        },
        "top_bot_user_agents": formatted_agents
    }


class UpdateBotBlockingRequest(BaseModel):
    enabled: bool


@app.put("/services/{service_id}/bot-blocking")
async def update_bot_blocking(
    service_id: int,
    request: UpdateBotBlockingRequest,
    db: Session = Depends(get_db)
):
    """
    Update bot blocking configuration for a service.
    """
    # Verify service exists
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Get or create config
    config = db.query(ServiceConfig).filter(ServiceConfig.service_id == service_id).first()
    
    if not config:
        config = ServiceConfig(
            service_id=service_id,
            block_bots_enabled=request.enabled
        )
        db.add(config)
    else:
        config.block_bots_enabled = request.enabled
    
    db.commit()
    db.refresh(config)
    
    return {
        "message": "Bot blocking configuration updated",
        "service_id": service_id,
        "block_bots_enabled": config.block_bots_enabled
    }


@app.get("/services/list")
async def list_services(db: Session = Depends(get_db)):
    """
    Get list of all services with watermarking status.
    
    Returns:
    - services: List of all services with id, name, target_url, and watermarking_enabled status
    """
    services = db.query(Service).all()
    
    results = []
    for service in services:
        results.append({
            "id": service.id,
            "name": service.name,
            "target_url": service.target_url,
            "watermarking_enabled": service.watermarking_enabled
        })
    
    return {"services": results}


@app.get("/services/{service_id}/watermarking")
async def get_watermarking_status(service_id: int, db: Session = Depends(get_db)):
    """
    Get watermarking status for a specific service.
    
    Returns:
    - service_id: Service ID
    - service_name: Service name
    - watermarking_enabled: Whether watermarking is enabled
    """
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    return {
        "service_id": service.id,
        "service_name": service.name,
        "watermarking_enabled": service.watermarking_enabled
    }


class ToggleWatermarkingRequest(BaseModel):
    """Request model for toggling watermarking."""
    enabled: bool


@app.post("/services/{service_id}/watermarking")
async def toggle_watermarking(
    service_id: int,
    request: ToggleWatermarkingRequest,
    db: Session = Depends(get_db)
):
    """
    Toggle watermarking for a service.
    
    Args:
    - service_id: Service ID
    - enabled: Whether to enable or disable watermarking
    
    Returns:
    - message: Success message
    - service_id: Service ID
    - service_name: Service name
    - watermarking_enabled: New watermarking status
    """
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    service.watermarking_enabled = request.enabled
    db.commit()
    db.refresh(service)
    
    return {
        "message": f"Watermarking {'enabled' if request.enabled else 'disabled'} for service '{service.name}'",
        "service_id": service.id,
        "service_name": service.name,
        "watermarking_enabled": service.watermarking_enabled
    }


class VerifyWatermarkRequest(BaseModel):
    """Request model for verifying watermark."""
    data: str


@app.post("/watermark/verify")
async def verify_watermark(request: VerifyWatermarkRequest, db: Session = Depends(get_db)):
    """
    Verify and extract watermark from leaked data.
    
    Args:
    - data: The data to check for watermark (JSON string or text)
    
    Returns:
    - watermark_found: Whether a watermark was found
    - raw_watermark: The raw base64-encoded watermark
    - decoded: Decoded watermark information
    - attribution: Human-readable attribution string
    """
    watermark = None
    
    # Try to parse as JSON first
    try:
        json_data = json.loads(request.data)
        watermark = extract_watermark_from_json(json_data)
    except json.JSONDecodeError:
        # Not JSON, try extracting from text
        watermark = extract_watermark_from_text(request.data)
    
    if not watermark:
        return {
            "watermark_found": False,
            "raw_watermark": "",
            "decoded": {},
            "attribution": "No watermark found in the provided data"
        }
    
    # Decode the watermark
    decoded_data = decode_watermark(watermark)
    
    if not decoded_data:
        return {
            "watermark_found": True,
            "raw_watermark": watermark,
            "decoded": {},
            "attribution": "Watermark found but could not be decoded (invalid format)"
        }
    
    # Get service and API key information
    service = db.query(Service).filter(Service.id == decoded_data["service_id"]).first()
    api_key_obj = db.query(ApiKey).filter(ApiKey.id == decoded_data["api_key_id"]).first()
    
    service_name = service.name if service else f"Unknown Service (ID: {decoded_data['service_id']})"
    api_key_masked = api_key_obj.key[:8] + "..." if api_key_obj else "Unknown"
    
    attribution = (
        f"Data leaked from service '{service_name}' "
        f"via API key {api_key_masked} "
        f"at {decoded_data['timestamp']} "
        f"(Request ID: {decoded_data['request_id']})"
    )
    
    return {
        "watermark_found": True,
        "raw_watermark": watermark,
        "decoded": {
            "service_id": decoded_data["service_id"],
            "service_name": service_name,
            "api_key_id": decoded_data["api_key_id"],
            "api_key_masked": api_key_masked,
            "request_id": decoded_data["request_id"],
            "timestamp": decoded_data["timestamp"]
        },
        "attribution": attribution
    }


@app.get("/services/bot-blocking")
async def get_all_bot_blocking_configs(db: Session = Depends(get_db)):
    """
    Get bot blocking configuration for all services.
    """
    services = db.query(Service).all()
    
    results = []
    for service in services:
        config = db.query(ServiceConfig).filter(ServiceConfig.service_id == service.id).first()
        enabled = config.block_bots_enabled if config else False
        
        results.append({
            "service_id": service.id,
            "service_name": service.name,
            "block_bots_enabled": enabled
        })
    
    return {"services": results}


@app.delete("/services/{service_id}")
async def delete_service(service_id: int, db: Session = Depends(get_db)):
    """
    Delete a service and all its related data.
    
    Cascade deletes:
    - All API keys for this service
    - All usage logs for this service
    - All bot detection logs for this service
    - Service configuration
    
    Control-plane endpoint - no authentication required.
    """
    # Check if service exists
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    service_name = service.name
    
    # Delete related data (cascade deletion)
    # 1. Delete all API keys for this service
    db.query(ApiKey).filter(ApiKey.service_id == service_id).delete()
    
    # 2. Delete all usage logs for this service
    db.query(UsageLog).filter(UsageLog.service_id == service_id).delete()
    
    # 3. Delete all bot detection logs for this service
    db.query(BotDetectionLog).filter(BotDetectionLog.service_id == service_id).delete()
    
    # 4. Delete service configuration
    db.query(ServiceConfig).filter(ServiceConfig.service_id == service_id).delete()
    
    # 5. Finally, delete the service itself
    db.delete(service)
    
    db.commit()
    
    return {
        "message": f"Service '{service_name}' and all related data deleted successfully",
        "service_id": service_id,
        "service_name": service_name
    }


# ============================================================================
# Adaptive Anomaly Detection Endpoints (Feature A)
# ============================================================================

@app.get("/security/anomaly/status")
async def get_anomaly_status():
    """
    Health of the anomaly detection subsystem: worker liveness (heartbeat)
    and whether the gateway is currently in degraded (fail-open) mode.
    """
    alive = await anomaly_gateway.worker_alive()
    return {
        "worker_alive": alive,
        "degraded_mode": anomaly_gateway.is_degraded(),
        "mode": "active" if alive else "degraded (fail-open, static controls only)",
        "thresholds": {
            "log": anomaly_cfg.THRESHOLD_LOG,
            "tarpit": anomaly_cfg.THRESHOLD_TARPIT,
            "block": anomaly_cfg.THRESHOLD_BLOCK,
        },
        "weights": {
            "global": anomaly_cfg.WEIGHT_GLOBAL,
            "per_key": anomaly_cfg.WEIGHT_PERKEY,
            "enumeration": anomaly_cfg.WEIGHT_ENUM,
            "auth_abuse": anomaly_cfg.WEIGHT_AUTH,
        },
    }


@app.get("/security/anomaly/scores")
async def get_anomaly_scores(
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """
    Recent elevated risk decisions (risk >= LOG threshold), newest first.
    Sub-scores are included so every decision is explainable.
    """
    limit = max(1, min(limit, 500))
    logs = db.query(AnomalyScoreLog).order_by(
        AnomalyScoreLog.created_at.desc()
    ).limit(limit).all()
    return {
        "count": len(logs),
        "scores": [
            {
                "id": log.id,
                "api_key_id": log.api_key_id,
                "service_id": log.service_id,
                "risk": round(log.risk, 4),
                "action": log.action,
                "endpoint": log.endpoint,
                "sub_scores": {
                    "global": round(log.score_global, 4),
                    "per_key": round(log.score_perkey, 4),
                    "enumeration": round(log.score_enum, 4),
                    "auth_abuse": round(log.score_auth, 4),
                },
                "timestamp": log.created_at.isoformat() if log.created_at else None,
            }
            for log in logs
        ],
    }


@app.get("/security/anomaly/risk/{api_key_id}")
async def get_current_risk(api_key_id: int):
    """
    The live cached risk decision for an API key (what the gateway would
    enforce right now). Empty if no recent score (neutral / fail-open).
    """
    action, risk = await anomaly_gateway.get_decision(api_key_id)
    return {
        "api_key_id": api_key_id,
        "action": action,
        "risk": round(risk, 4) if risk is not None else None,
        "scored": risk is not None,
    }


class SimulateAttackRequest(BaseModel):
    # "credential_stuffing" | "enumeration" | "low_and_slow" | "all"
    scenario: str = "all"


# Attack presets: (generator, warmup+attack event counts) kept modest so a
# button click returns in ~1-2s while still crossing the detection threshold.
_ATTACK_SCENARIOS = {
    "credential_stuffing": 120,
    "enumeration": 150,
    "low_and_slow": 200,
}


@app.post("/security/anomaly/simulate")
def simulate_anomaly_attack(request: SimulateAttackRequest):
    """
    Drive synthetic attack traffic through the REAL scoring pipeline so the
    dashboard visibly populates. This is not a mock: every event runs through
    the same ``AnomalyScorer`` (per-key baselines -> global model -> fusion),
    writes the same per-key Redis state, caches the same decision, and persists
    to the same ``AnomalyScoreLog`` table that live proxied traffic uses.

    Each run uses fresh demo key ids in the 9xx,xxx,xxx range, so every attacker
    warms up a baseline from scratch and then turns malicious (account-takeover
    shape) — independent of real traffic and of previous runs.

    Sync endpoint: FastAPI runs it in a threadpool (the scorer uses sync Redis).
    """
    import random
    import redis as sync_redis
    from app.anomaly.worker import AnomalyScorer, _persist_elevated
    from simulator.traffic import (
        LABEL_NORMAL, NormalClient, credential_stuffing, enumeration,
        low_and_slow, merge_timelines,
    )

    scenario = request.scenario.lower().strip()
    if scenario == "all":
        scenarios = list(_ATTACK_SCENARIOS.keys())
    elif scenario in _ATTACK_SCENARIOS:
        scenarios = [scenario]
    else:
        raise HTTPException(
            status_code=400,
            detail=f"unknown scenario '{scenario}'. Valid: "
                   f"{', '.join(_ATTACK_SCENARIOS)}, all",
        )

    # Connect to the same Redis the worker/gateway use. If it's down, the whole
    # feature is offline — say so clearly rather than silently doing nothing.
    try:
        r = sync_redis.Redis.from_url(
            anomaly_cfg.REDIS_URL, decode_responses=True,
            socket_connect_timeout=2, socket_timeout=2,
        )
        r.ping()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"anomaly scoring engine unavailable (Redis unreachable): {exc}",
        )

    generators = {
        "credential_stuffing": credential_stuffing,
        "enumeration": enumeration,
        "low_and_slow": low_and_slow,
    }
    service_id = 999  # reserved demo service
    scorer = AnomalyScorer(r)
    results = []
    local = defaultdict(int)  # this run's own action tally (warmup + attack)

    for scen in scenarios:
        # Fresh attacker identity each run -> honest cold-start + warmup.
        key_id = 900_000_000 + random.randint(0, 89_999_999)
        rng = random.Random(key_id)
        t0 = time.time()

        # Warmup on a SIMULATED clock spanning several enumeration windows, so the
        # windowed-HLL baseline (enum_n) actually forms before the attack — this
        # is what lets the enumeration / low-and-slow detectors fire (they are in
        # cold-start until the key has multiple completed windows of history).
        # Runs instantly regardless of span because the pipeline uses event time.
        window = anomaly_cfg.ENUM_WINDOW_SECONDS
        warmup_span = window * (anomaly_cfg.ENUM_MERGE_BUCKETS + 2)
        base_interval = max(3.0, window / 12.0)   # ~12 benign events per window
        warmup = list(
            NormalClient(key_id, service_id, rng, base_interval=base_interval)
            .events(t0, t0 + warmup_span)
        )
        attack_start = t0 + warmup_span + 10
        attack = generators[scen](key_id, service_id, attack_start,
                                  n=_ATTACK_SCENARIOS[scen])
        timeline = merge_timelines(warmup, attack)

        from app.anomaly.worker import bump_counters
        flagged = tarpit = blocked = 0
        peak_risk = 0.0
        first_detect = None
        attack_seen = 0
        final_action = "allow"
        for le in timeline:
            decision = scorer.process_event(le.ev)
            bump_counters(r, decision)
            _persist_elevated(decision, le.ev)
            local[decision.action] += 1
            if le.label != LABEL_NORMAL:
                attack_seen += 1
                is_flag = decision.action in (ANOMALY_TARPIT, ANOMALY_BLOCK)
                if is_flag:
                    flagged += 1
                    if decision.action == ANOMALY_BLOCK:
                        blocked += 1
                    else:
                        tarpit += 1
                    if first_detect is None:
                        first_detect = attack_seen
                peak_risk = max(peak_risk, decision.risk)
                final_action = decision.action

        results.append({
            "scenario": scen,
            "demo_key_id": key_id,
            "warmup_events": len(warmup),
            "attack_events": attack_seen,
            "flagged": flagged,
            "blocked": blocked,
            "tarpitted": tarpit,
            "recall": round(flagged / attack_seen, 3) if attack_seen else 0.0,
            "peak_risk": round(peak_risk, 3),
            "first_detection_after": first_detect,
            "final_action": final_action,
        })

    # Store this run's self-contained totals as the "last demo run", so the
    # dashboard overview shows THIS simulation's numbers — independent of any
    # replay or live traffic (which is why the two demos no longer overwrite
    # each other's headline stats).
    processed = sum(local.values())
    allowed = local.get("allow", 0)
    flagged = local.get("log", 0) + local.get("tarpit", 0) + local.get("block", 0)
    try:
        r.set("anom:demo:summary", json.dumps({
            "type": "simulate",
            "totals": {
                "processed": processed,
                "allowed": allowed,
                "flagged": flagged,
                "allowed_pct": round(100.0 * allowed / processed, 2) if processed else 0.0,
                "flagged_pct": round(100.0 * flagged / processed, 3) if processed else 0.0,
            },
            "scenarios": results,
        }))
    except Exception:
        pass

    return {
        "message": "Attack traffic scored through the live pipeline. "
                   "Open the recent-decisions table to inspect the results.",
        "scenarios_run": len(results),
        "results": results,
    }


@app.get("/security/anomaly/overview")
def get_anomaly_overview():
    """
    Live traffic totals: how many requests the scorer has seen and how they
    were dispatched (allow / log / tarpit / block). This is what makes the
    picture believable — the overwhelming majority of real traffic is allowed.
    """
    import redis as sync_redis
    from app.anomaly.worker import COUNTER_KEYS

    replay_running = False
    last_run = None
    try:
        r = sync_redis.Redis.from_url(
            anomaly_cfg.REDIS_URL, decode_responses=True,
            socket_connect_timeout=2, socket_timeout=2,
        )
        vals = r.mget([f"anom:counter:{k}" for k in COUNTER_KEYS])
        replay_running = bool(r.get("anom:replay:running"))
        raw_summary = r.get("anom:demo:summary")
        if raw_summary:
            last_run = json.loads(raw_summary)
    except Exception:
        vals = [None] * len(COUNTER_KEYS)

    counts = {k: int(v or 0) for k, v in zip(COUNTER_KEYS, vals)}
    # last_replay is only populated when the most recent demo was a replay, so
    # the frontend's injected-attack card appears only for replays.
    last_replay = last_run if (last_run and last_run.get("type") == "replay") else None

    # Show the LAST DEMO RUN's own self-contained totals (replay or simulate),
    # so each demo displays its own numbers and clicking one never rewrites the
    # other's headline stats. While a replay is streaming we instead show the
    # live counters so the user watches them climb in real time.
    if last_run and last_run.get("totals") and not replay_running:
        t = last_run["totals"]
        return {
            "processed": t["processed"],
            "allowed": t["allowed"],
            "flagged": t["flagged"],
            "allowed_pct": t["allowed_pct"],
            "flagged_pct": t["flagged_pct"],
            "source": last_run.get("type", "last_run"),
            "replay_running": replay_running,
            "last_run": last_run,
            "last_replay": last_replay,
        }

    processed = counts["processed"]
    flagged = counts["log"] + counts["tarpit"] + counts["block"]
    return {
        "processed": processed,
        "allowed": counts["allow"],
        "logged": counts["log"],
        "tarpitted": counts["tarpit"],
        "blocked": counts["block"],
        "flagged": flagged,
        "allowed_pct": round(100.0 * counts["allow"] / processed, 2) if processed else 0.0,
        "flagged_pct": round(100.0 * flagged / processed, 3) if processed else 0.0,
        "source": "live_counters",
        "replay_running": replay_running,
        "last_run": last_run,
        "last_replay": last_replay,
    }


class ReplayRequest(BaseModel):
    events: int = 4000          # real requests to stream through the scorer
    inject_attack: bool = True  # inject one realistic attack from a real client


# Bundled sample ships with the code (Docker COPY), so the real-traffic replay
# works on a deployed instance even though the full 20MB dataset is gitignored.
_ACCESS_LOG_SAMPLE = "simulator/sample_data/nasa_sample.log.gz"


def _resolve_access_log() -> Optional[str]:
    """Full local dataset if downloaded, else the bundled sample, else None."""
    override = os.getenv("AEGIS_ACCESS_LOG")
    if override and os.path.exists(override):
        return override
    if os.path.exists("data/nasa_jul95.gz"):
        return "data/nasa_jul95.gz"
    if os.path.exists(_ACCESS_LOG_SAMPLE):
        return _ACCESS_LOG_SAMPLE
    return None


def _replay_worker(events_target: int, inject_attack: bool) -> None:
    """
    Background job: stream REAL NASA-HTTP traffic through the live scorer,
    updating the live counters as it goes (so the dashboard fills in real time)
    and storing a final summary in Redis. Runs in a daemon thread.
    """
    import random
    import redis as sync_redis
    from collections import Counter
    from app.anomaly.worker import (
        AnomalyScorer, bump_counters, COUNTER_KEYS, _persist_elevated,
    )
    from app.anomaly.risk_engine import ACTION_ALLOW
    from simulator.access_log_loader import iter_access_log
    from simulator.traffic import low_and_slow

    data_path = _resolve_access_log()
    r = sync_redis.Redis.from_url(anomaly_cfg.REDIS_URL, decode_responses=True)

    try:
        events = list(iter_access_log(data_path, limit=events_target))
        r.delete(*[f"anom:counter:{k}" for k in COUNTER_KEYS])

        # Clean per-key state so each replay is reproducible. Critical because the
        # NASA timestamps are fixed (1995): re-running reuses the same HLL window
        # buckets, and HLL only counts up — without this, distinct-id counts
        # accumulate across runs, saturate, and spuriously flag real clients.
        for pattern in ("anom:stats:*", "anom:rate:*", "anom:wreq:*",
                        "anom:hll:*", "anom:risk:*"):
            batch = []
            for k in r.scan_iter(match=pattern, count=500):
                batch.append(k)
                if len(batch) >= 500:
                    r.delete(*batch)
                    batch = []
            if batch:
                r.delete(*batch)

        scorer = AnomalyScorer(r)
        split = int(len(events) * 0.6)
        warmup, evalset = events[:split], events[split:]

        # Replay-scoped tally: counts ONLY this replay's events, so the overview
        # it produces reconciles exactly with the injected-attack recall (the
        # global counters also see live proxy/simulate traffic and would drift).
        local = Counter()
        for ev in warmup:
            d = scorer.process_event(ev)
            bump_counters(r, d)
            local[d.action] += 1

        injected, injected_key = [], None
        if inject_attack and evalset:
            freq = Counter(ev.api_key_id for ev in warmup)
            cand = [k for k, c in freq.most_common(30) if c >= anomaly_cfg.N_MIN + 5]
            if cand:
                injected_key = cand[0]
                t0 = evalset[0].ts + 5.0
                injected = [le.ev for le in low_and_slow(injected_key, 999, t0, n=120)]

        timeline = sorted(list(evalset) + injected, key=lambda ev: ev.ts)
        injected_ids = {id(ev) for ev in injected}
        flagged_samples, attack_flagged, attack_total = [], 0, 0
        for ev in timeline:
            d = scorer.process_event(ev)
            bump_counters(r, d)
            _persist_elevated(d, ev)
            local[d.action] += 1
            if id(ev) in injected_ids:
                attack_total += 1
                if d.action in (ANOMALY_TARPIT, ANOMALY_BLOCK):
                    attack_flagged += 1
            elif d.action != ACTION_ALLOW and len(flagged_samples) < 8:
                flagged_samples.append({
                    "api_key_id": ev.api_key_id, "endpoint": ev.path,
                    "action": d.action, "risk": round(d.risk, 3),
                })

        processed = sum(local.values())
        allowed = local.get("allow", 0)
        flagged = local.get("log", 0) + local.get("tarpit", 0) + local.get("block", 0)
        summary = {
            "type": "replay",
            "distinct_real_clients": len(set(ev.api_key_id for ev in events)),
            "totals": {
                "processed": processed,
                "allowed": allowed,
                "flagged": flagged,
                "allowed_pct": round(100.0 * allowed / processed, 2) if processed else 0.0,
                "flagged_pct": round(100.0 * flagged / processed, 3) if processed else 0.0,
            },
            "injected_attack": {
                "enabled": bool(injected_key),
                "client_id": injected_key,
                "events": attack_total,
                "detected": attack_flagged,
                "recall": round(attack_flagged / attack_total, 3) if attack_total else 0.0,
            },
            "real_flagged_samples": flagged_samples,
        }
        r.set("anom:demo:summary", json.dumps(summary))
    except Exception as exc:
        logger.warning("replay worker failed: %s", exc)
    finally:
        try:
            r.delete("anom:replay:running")
        except Exception:
            pass


@app.post("/security/anomaly/replay")
def replay_real_traffic(request: ReplayRequest):
    """
    Replay REAL HTTP traffic (NASA-HTTP access log) through the live scorer, so
    the dashboard shows the believable picture: thousands of genuine requests
    from thousands of real client IPs, ~99.9% allowed, and only a true handful
    flagged — the actual high-volume crawlers plus (optionally) one realistic
    attack injected from a previously-benign real client (the ATO shape).

    Runs in the background so the dashboard's counters visibly climb in real
    time. Local-only: needs the NASA dataset at data/nasa_jul95.gz (gitignored).
    Download once:  curl -sSL -o data/nasa_jul95.gz \
        https://ita.ee.lbl.gov/traces/NASA_access_log_Jul95.gz
    """
    import threading
    import redis as sync_redis

    data_path = _resolve_access_log()
    if not data_path:
        raise HTTPException(
            status_code=503,
            detail="no real-traffic dataset available (neither the full NASA-HTTP "
                   "download nor the bundled sample was found).",
        )
    try:
        r = sync_redis.Redis.from_url(
            anomaly_cfg.REDIS_URL, decode_responses=True,
            socket_connect_timeout=2, socket_timeout=2,
        )
        r.ping()
        if r.get("anom:replay:running"):
            raise HTTPException(status_code=409, detail="a replay is already in progress")
        r.set("anom:replay:running", "1", ex=300)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"anomaly scoring engine unavailable (Redis unreachable): {exc}",
        )

    n = max(500, min(request.events, 20000))
    threading.Thread(
        target=_replay_worker, args=(n, request.inject_attack),
        name="anomaly-replay", daemon=True,
    ).start()
    return {
        "status": "started",
        "events": n,
        "message": "Replaying real NASA-HTTP traffic through the live scorer. "
                   "Watch the traffic overview and recent-decisions table fill in.",
    }


# ============================================================================
# Cryptographic Transparency Endpoints (Merkle Trees)
# ============================================================================

@app.get("/transparency/merkle-latest")
async def get_latest_merkle_root(db: Session = Depends(get_db)):
    """
    Get the latest computed Merkle root.
    
    Returns the most recent Merkle root with metadata including time range
    and request count.
    
    Returns:
        Latest Merkle root data or 404 if no roots computed yet
    """
    # Get the latest Merkle root (highest ID)
    latest_root = db.query(MerkleRoot).order_by(MerkleRoot.id.desc()).first()
    
    if not latest_root:
        raise HTTPException(
            status_code=404,
            detail="No Merkle roots computed yet. Make requests through the gateway to generate roots."
        )
    
    return {
        "batch_id": latest_root.id,
        "merkle_root": latest_root.merkle_root,
        "start_time": latest_root.start_time.isoformat(),
        "end_time": latest_root.end_time.isoformat(),
        "request_count": latest_root.request_count,
        "created_at": latest_root.created_at.isoformat()
    }


@app.get("/transparency/merkle-history")
async def get_merkle_history(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """
    Get historical Merkle roots with pagination.
    
    Args:
        limit: Maximum number of roots to return (default: 50, max: 100)
        offset: Number of roots to skip (default: 0)
    
    Returns:
        List of Merkle roots with pagination metadata
    """
    # Validate and cap limit
    if limit < 1:
        limit = 50
    if limit > 100:
        limit = 100
    
    if offset < 0:
        offset = 0
    
    # Get total count
    total = db.query(func.count(MerkleRoot.id)).scalar() or 0
    
    # Get paginated roots (newest first)
    roots = db.query(MerkleRoot).order_by(
        MerkleRoot.id.desc()
    ).limit(limit).offset(offset).all()
    
    return {
        "merkle_roots": [
            {
                "batch_id": root.id,
                "merkle_root": root.merkle_root,
                "start_time": root.start_time.isoformat(),
                "end_time": root.end_time.isoformat(),
                "request_count": root.request_count,
                "created_at": root.created_at.isoformat()
            }
            for root in roots
        ],
        "total": total,
        "limit": limit,
        "offset": offset
    }


@app.get("/transparency/verify/{batch_id}")
async def verify_merkle_batch(
    batch_id: int,
    db: Session = Depends(get_db)
):
    """
    Get all hashes in a Merkle batch for client-side verification.
    
    Returns the list of hashes that were used to compute the Merkle root,
    allowing clients to independently verify the computation.
    
    Args:
        batch_id: ID of the Merkle batch to verify
    
    Returns:
        Batch hashes and expected root for verification
    """
    # Get the Merkle root record
    merkle_root = db.query(MerkleRoot).filter(MerkleRoot.id == batch_id).first()
    
    if not merkle_root:
        raise HTTPException(
            status_code=404,
            detail=f"Merkle batch {batch_id} not found"
        )
    
    # Get all hashes in this batch (ordered by timestamp)
    hashes = db.query(RequestHash).filter(
        RequestHash.merkle_batch_id == batch_id
    ).order_by(RequestHash.timestamp.asc()).all()
    
    return {
        "batch_id": batch_id,
        "hashes": [h.hash for h in hashes],
        "expected_root": merkle_root.merkle_root,
        "request_count": len(hashes),
        "start_time": merkle_root.start_time.isoformat(),
        "end_time": merkle_root.end_time.isoformat()
    }


@app.get("/transparency/blockchain/{batch_id}")
async def get_blockchain_proof(
    batch_id: int,
    db: Session = Depends(get_db)
):
    """
    Get blockchain anchoring proof for a Merkle batch.
    
    Returns transaction hash, block number, and Etherscan link if the batch
    has been anchored to the Sepolia blockchain.
    
    Args:
        batch_id: ID of the Merkle batch
    
    Returns:
        Blockchain anchoring information or status
    """
    merkle_root = db.query(MerkleRoot).filter(MerkleRoot.id == batch_id).first()
    
    if not merkle_root:
        raise HTTPException(
            status_code=404,
            detail=f"Batch {batch_id} not found"
        )
    
    if not merkle_root.is_anchored:
        return {
            "batch_id": batch_id,
            "is_anchored": False,
            "message": "This batch has not been anchored to blockchain yet"
        }
    
    return {
        "batch_id": batch_id,
        "is_anchored": True,
        "tx_hash": merkle_root.tx_hash,
        "block_number": merkle_root.block_number,
        "anchored_at": merkle_root.anchored_at.isoformat() if merkle_root.anchored_at else None,
        "etherscan_url": f"https://sepolia.etherscan.io/tx/{merkle_root.tx_hash}"
    }
