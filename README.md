# GaaS Gateway

**Gateway-as-a-Service (GaaS)** is a modern API gateway platform that allows users to register APIs, control access via API keys, enforce per-key rate limits, monitor usage, and apply usage-based billing — all without modifying the original backend API.

The gateway sits as a reverse proxy between clients and APIs, giving creators control over security, traffic, and monetization even if they do not own the original API infrastructure.

## Problem Statement

Public APIs face systemic problems:

- **No access control** once an API endpoint is public
- **Uncontrolled scraping and bot abuse**
- **No built-in monetization**
- **No per-consumer rate limits**
- **Limited visibility** into who is using the data

Traditional API gateways solve this, but they are complex to configure and maintain.

GaaS Gateway provides these capabilities as a lightweight, developer-friendly service.

## What GaaS Gateway Solves

- Adds a control layer on top of any HTTP API
- Provides API key–based access control
- Enforces rate limits per API key
- Tracks usage analytics
- Supports usage-based billing
- Offers a Cloudflare-style management dashboard

## Motivation

The motivation behind GaaS Gateway is to provide developers and organizations with:

1. **Simplified API Management**: A single entry point for all API requests, reducing complexity in client applications
2. **Enhanced Security**: Centralized API key management and authentication, protecting backend services from direct exposure
3. **Fair Resource Usage**: Token bucket-based rate limiting ensures fair distribution of resources and prevents API abuse
4. **Usage Insights**: Built-in analytics and logging to understand API usage patterns and optimize performance
5. **Developer-Friendly**: Easy service registration, automatic API key generation, and comprehensive documentation

## High-Level Architecture

```
Client
  │
  │  HTTP request + X-API-Key
  ▼
┌──────────────────────────────┐
│        GaaS Gateway           │
│                              │
│  ┌────────────────────────┐  │
│  │ API Key Authentication │  │
│  └────────────────────────┘  │
│                              │
│  ┌────────────────────────┐  │
│  │ Per-Key Rate Limiting  │  │
│  │ (Token Bucket)         │  │
│  └────────────────────────┘  │
│                              │
│  ┌────────────────────────┐  │
│  │ Billing & Usage Log    │  │
│  └────────────────────────┘  │
│                              │
│  ┌────────────────────────┐  │
│  │ Reverse Proxy Engine   │  │
│  └────────────────────────┘  │
│                              │
└──────────────┬───────────────┘
               │
               ▼
         Backend API
```

## Core Concepts

### 1. Services

A service represents a backend API registered with the gateway.

Each service has:
- `id`
- `name`
- `target_url`
- One or more API keys

Clients never call the backend directly — all traffic flows through `/proxy/{service_id}`.

### 2. API Keys (Per Service)

Each service can have multiple API keys.

Keys are:
- Independently rate-limited
- Independently billed
- Individually revocable
- Scoped to a service
- Revealed only once when generated

This allows:
- Different consumers
- Different pricing
- Different limits

### 3. Request Flow

Client sends request:
```bash
GET /proxy/3
X-API-Key: <api_key>
```

Gateway performs:
1. API key validation (must belong to service)
2. Per-key rate limiting
3. Usage & billing logging
4. Request is proxied to `service.target_url`
5. Response is returned unchanged to the client

### Core Components

1. **Authentication Service**: Validates API keys and manages user sessions
2. **Rate Limiter**: Implements token bucket algorithm for per-API-key rate limiting
3. **Request Proxy**: Forwards HTTP requests to registered backend services
4. **Usage Analytics**: Tracks and logs all successful API requests
5. **Service Registry**: Manages registered services and their target URLs

## How Gateway-as-a-Service Works

### 1. Service Registration

Users register their backend services with the gateway:

```bash
POST /register-api
{
  "name": "My API Service",
  "target_url": "https://api.example.com"
}
```

The gateway:
- Creates a service entry linked to a user
- Auto-generates a default user if none exists
- Returns a `service_id` and `gateway_url` (e.g., `/proxy/1`)
- Provides an API key for authentication (returned once during user creation)

### 2. Request Flow

When a client makes a request:

1. **Authentication**: Client includes `X-API-Key` header
   ```bash
   GET /proxy/1
   Headers: X-API-Key: <api_key>
   ```

2. **Rate Limiting**: Gateway checks if the API key has available tokens
   - Token bucket algorithm: 10 tokens, refills at 10 tokens per 60 seconds
   - Returns HTTP 429 if limit exceeded

3. **Service Resolution**: Gateway looks up the service by `service_id` and retrieves the `target_url`

4. **Request Proxying**: Gateway forwards the request to the backend service
   - Preserves HTTP method, headers, query parameters, and body
   - Excludes sensitive headers (host, content-length, X-API-Key)

5. **Response Handling**: Gateway returns the backend response
   - Status code, headers, and body are forwarded to the client

6. **Usage Logging**: Successful requests (2xx, 3xx) are logged to the database
   - Tracks: `service_id`, `api_key`, `timestamp`

### 3. Usage Analytics

Users can query usage statistics:

```bash
GET /usage/{service_id}
Headers: X-API-Key: <api_key>
```

Returns:
- Total request count for the service
- Request count grouped by API key

## Features

### 🧠 Adaptive Behavioral Anomaly Detection (Feature A)
AI-powered security layer that learns each API key's normal behavior and scores every request in real time — catching attacks that use *valid credentials and well-formed requests* and thus slip past static controls.

- **Two detectors, fused**: a global online model (River `HalfSpaceTrees`) for population-level outliers + per-key EWMA baselines and windowed HyperLogLog for per-entity drift and enumeration.
- **Async, fail-open**: scoring runs off the hot path via Redis Streams; the gateway's only cost is one cached-score lookup. If the worker/Redis is down, static controls keep enforcing.
- **Graduated response**: allow → log → **tarpit** (inject latency + rate cut) → block.
- **Measured on real traffic** (NASA-HTTP, 40k real events / 3,401 real clients, attacks injected from previously-benign real IPs): precision **0.955**, recall **0.926**, FPR **0.001** — and 37 of 39 false positives trace to 2 genuine high-volume crawlers.
- **Synthetic harness**: precision **1.000**, recall **0.896**, zero false positives.
- Details, real-traffic caveats & runbook: [FEATURE_A_ANOMALY_DETECTION.md](FEATURE_A_ANOMALY_DETECTION.md) · code in [app/anomaly/](app/anomaly/) · reproduce with `python -m simulator.evaluate_real`.

### 🔐 Authentication & Security
- **API Key Authentication**: Secure API key-based authentication for all proxy requests
- **Header-based Auth**: Simple `X-API-Key` header for easy integration
- **User Management**: Automatic user creation with secure API key generation
- **One-time Key Reveal**: API keys can be retrieved once for security

### ⚡ Rate Limiting

**Model:**
- Token bucket per API key
- Configurable per key:
  - Requests per window
  - Window duration (seconds)

**Behavior:**
- Tokens refill continuously
- If tokens are exhausted: Gateway returns HTTP 429

**Configuration:**
- Users can modify rate limits per API key via the dashboard
- Default: 10 requests per 60 seconds
- Supports per-key overrides via `rate_limit_requests` and `rate_limit_window_seconds`

### 🔄 Request Proxying
- **Full HTTP Support**: Supports GET, POST, PUT, DELETE methods
- **Header Preservation**: Forwards safe headers while excluding sensitive ones
- **Query Parameter Forwarding**: All query parameters are preserved
- **Request Body Support**: Handles request bodies for POST, PUT, DELETE
- **Timeout Handling**: Graceful timeout handling (30s overall, 10s connect)
- **Error Handling**: Proper HTTP status codes for gateway errors (502, 504)

### 📊 Usage Analytics

Every successful request (2xx/3xx) is logged.

**Tracked dimensions:**
- Service
- API key
- Timestamp
- Request count

**Endpoints:**
- `GET /usage/{service_id}`

**Returns:**
- Total requests
- Requests grouped by API key

### 💰 Billing System (Current Implementation)

**Pricing Model:**
- Usage-based billing
- Each API key has:
  - `price_per_request` (default: 0.001)
  - `total_cost` (accumulated)

**Billing Flow:**
- Each successful request: `total_cost += price_per_request`
- Billing is accumulated in real time
- Pricing can be customized per API key

**Billing APIs:**
- `GET /billing/summary` - Aggregated billing overview
- `GET /billing/api-keys` - Per-key billing details
- `PUT /api-keys/{key_id}/pricing` - Update price per request
- `POST /billing/reset` - Start new billing cycle

⚠️ **Note**: Billing is simulated (no payments). This is intentional for demo and academic evaluation.

### 🛠️ Developer Experience
- **Auto-generated API Keys**: Secure token generation using `secrets.token_urlsafe()`
- **Service Registration**: Simple REST API for registering backend services
- **Interactive API Docs**: Built-in Swagger UI at `/docs`
- **Health Checks**: Health check endpoint for monitoring

## Frontend Dashboard

The frontend provides a professional management UI with:

### Pages

**Overview**
- Total APIs
- Requests
- Health status

**APIs**
- Register services
- View gateway URLs

**API Keys**
- Generate keys
- Revoke keys
- Configure rate limits
- Configure pricing

**Usage**
- Per-service analytics

**Billing**
- Per-key costs
- Aggregated totals

**Security**
- Key management
- Best practices

All data shown is backed by real backend state.

## Tech Stack

### Backend Framework
- **FastAPI**: Modern, fast web framework for building APIs with Python
- **Python 3.10+**: Leveraging modern Python features and type hints

### Database & ORM
- **SQLite**: Lightweight, file-based database for development
- **SQLAlchemy 2.0**: Modern ORM with async support and type safety

### HTTP Client
- **httpx**: Async HTTP client for proxying requests to backend services

### Data Validation
- **Pydantic**: Data validation using Python type annotations
- **HttpUrl**: Built-in URL validation for service registration

### Server
- **Uvicorn**: ASGI server for running FastAPI applications

## Limitations

### Current Limitations

1. **In-Memory Rate Limiting**: Rate limiting uses in-memory storage, which means:
   - Not suitable for multi-instance deployments
   - Rate limit data is lost on server restart
   - **Note**: Redis would be used in production for distributed rate limiting

2. **SQLite Database**: Using SQLite has limitations:
   - Not suitable for high-concurrency scenarios
   - Single-writer limitation
   - No built-in replication or clustering

3. **Single User Model**: Currently supports a single default user per instance
   - No multi-tenant support
   - Limited user management capabilities

4. **No Request/Response Transformation**: 
   - No request/response body transformation
   - No header manipulation beyond basic filtering
   - No request routing based on path patterns

5. **Limited Error Handling**:
   - Basic timeout and connection error handling
   - No retry mechanisms
   - No circuit breaker pattern

6. **No Caching**: 
   - No response caching capabilities
   - Every request is forwarded to the backend

7. **Security Considerations**:
   - API keys stored in plain text (should be hashed in production)
   - No key rotation mechanism
   - No OAuth2 or JWT support

## Future Scope

### Short-term Enhancements

1. **Distributed Rate Limiting**
   - Integrate Redis for distributed token bucket storage
   - Support for multi-instance deployments
   - Persistent rate limit data

2. **Enhanced User Management**
   - Multi-user support with proper user registration
   - User roles and permissions
   - API key rotation and expiration

3. **Database Migration**
   - PostgreSQL/MySQL support for production
   - Database migration system (Alembic)
   - Connection pooling and optimization

4. **Request/Response Transformation**
   - Request body transformation
   - Response modification
   - Header manipulation rules

### Medium-term Features

5. **Advanced Routing**
   - Path-based routing (e.g., `/api/v1/*` → service A, `/api/v2/*` → service B)
   - Load balancing across multiple backend instances
   - Health checks and automatic failover

6. **Caching Layer**
   - Response caching with configurable TTL
   - Cache invalidation strategies
   - Cache key generation based on request parameters

7. **Enhanced Security**
   - API key hashing (bcrypt/argon2)
   - OAuth2 and JWT support
   - IP whitelisting/blacklisting
   - Request signing and verification

8. **Monitoring & Observability**
   - Prometheus metrics export
   - Distributed tracing (OpenTelemetry)
   - Real-time dashboards
   - Alerting for rate limit violations

### Long-term Vision

9. **Multi-tenancy**
   - Organization/workspace support
   - Per-organization rate limits and quotas
   - Billing and usage-based pricing

10. **API Gateway Features**
    - GraphQL support
    - WebSocket proxying
    - gRPC support
    - Request/response compression

11. **Developer Portal**
    - Self-service API key management
    - Usage analytics dashboards
    - API documentation generation
    - Developer onboarding flows

12. **High Availability**
    - Multi-region deployment
    - Automatic failover
    - Zero-downtime deployments
    - Database replication and sharding

## Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Setup

1. **Clone the repository** (if applicable) or navigate to the project directory

2. **Create a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**:
   ```bash
   uvicorn main:app --reload
   ```

The API will be available at `http://localhost:8000`

## API Documentation

Once the server is running, you can access:

- **Interactive API docs (Swagger UI)**: `http://localhost:8000/docs`
- **Alternative docs (ReDoc)**: `http://localhost:8000/redoc`

## Project Structure

```
gaas-gateway/
├── app/
│   ├── __init__.py
│   ├── database.py      # Database configuration and session management
│   └── models.py         # SQLAlchemy models (User, Service, UsageLog, etc.)
├── main.py               # FastAPI application entry point
├── requirements.txt      # Python dependencies
├── gaas_gateway.db      # SQLite database (auto-created)
└── README.md            # This file
```

## Quick Start

1. **Register a service**:
   ```bash
   curl -X POST http://localhost:8000/register-api \
     -H "Content-Type: application/json" \
     -d '{"name": "Example API", "target_url": "https://httpbin.org/get"}'
   ```

2. **Get your API key** (first time only):
   ```bash
   curl http://localhost:8000/me/api-key
   ```

3. **Proxy a request**:
   ```bash
   curl http://localhost:8000/proxy/1 \
     -H "X-API-Key: YOUR_API_KEY"
   ```

4. **Check usage statistics**:
   ```bash
   curl http://localhost:8000/usage/1 \
     -H "X-API-Key: YOUR_API_KEY"
   ```

## Database

The application uses SQLite for persistence. The database file (`gaas_gateway.db`) is created automatically in the project root when the application starts.

**Note**: For production deployments, consider migrating to PostgreSQL or MySQL for better performance and scalability.

## License

[Specify your license here]

## Contributing

[Add contribution guidelines if applicable]

## Support

For issues, questions, or contributions, please [add your contact/support information].
