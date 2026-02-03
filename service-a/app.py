"""
Service A - Orders Service
==========================
Zero Trust Implementation:
1. Validates incoming user JWT tokens from Keycloak
2. Uses client credentials (service account) to call Service B
3. Propagates correlation IDs for tracing
4. Implements least privilege access
"""

import os
import logging
import uuid
from functools import wraps
from datetime import datetime

import requests
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from jose import jwt, JWTError
from cachetools import TTLCache

# ============================================
# Configuration
# ============================================
app = Flask(__name__)
CORS(app, origins=["http://localhost:3000", "http://127.0.0.1:3000"])

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Environment configuration
SERVICE_NAME = os.getenv("SERVICE_NAME", "orders-service")
PORT = int(os.getenv("PORT", 5001))
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080/auth")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "zero-trust-demo")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "orders-service")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "orders-service-secret")
SERVICE_B_URL = os.getenv("SERVICE_B_URL", "http://service-b:5002")
SERVICE_B_AUDIENCE = os.getenv("SERVICE_B_AUDIENCE", "inventory-service")

# Token cache for service-to-service tokens (TTL: 4 minutes, max 100 entries)
service_token_cache = TTLCache(maxsize=100, ttl=240)

# JWKS cache
jwks_cache = {"keys": None, "fetched_at": None}

# ============================================
# Mock Data (In real app, this would be a database)
# ============================================
ORDERS = {
    "ORD-001": {
        "id": "ORD-001",
        "user_id": "testuser",
        "items": [
            {"product_id": "PROD-001", "quantity": 2, "price": 29.99},
            {"product_id": "PROD-002", "quantity": 1, "price": 49.99}
        ],
        "status": "pending",
        "total": 109.97,
        "created_at": "2024-01-15T10:30:00Z"
    },
    "ORD-002": {
        "id": "ORD-002",
        "user_id": "testuser",
        "items": [
            {"product_id": "PROD-003", "quantity": 3, "price": 15.00}
        ],
        "status": "shipped",
        "total": 45.00,
        "created_at": "2024-01-14T08:00:00Z"
    }
}

# ============================================
# JWT / Keycloak Utilities
# ============================================
def get_keycloak_public_keys():
    """Fetch JWKS from Keycloak for token validation."""
    global jwks_cache
    
    # Return cached keys if available and recent
    if jwks_cache["keys"] and jwks_cache["fetched_at"]:
        age = (datetime.now() - jwks_cache["fetched_at"]).seconds
        if age < 300:  # Cache for 5 minutes
            return jwks_cache["keys"]
    
    try:
        jwks_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
        response = requests.get(jwks_url, timeout=10)
        response.raise_for_status()
        jwks_cache["keys"] = response.json()
        jwks_cache["fetched_at"] = datetime.now()
        logger.info(f"Fetched JWKS from Keycloak: {jwks_url}")
        return jwks_cache["keys"]
    except Exception as e:
        logger.error(f"Failed to fetch JWKS: {e}")
        if jwks_cache["keys"]:
            return jwks_cache["keys"]  # Return stale cache as fallback
        raise


def validate_token(token: str) -> dict:
    """
    Validate JWT token from Keycloak.
    Zero Trust: Every request must be authenticated.
    """
    try:
        jwks = get_keycloak_public_keys()
        
        # Get the key ID from token header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        
        # Find the matching key
        rsa_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                rsa_key = key
                break
        
        if not rsa_key:
            raise JWTError("Unable to find matching key")
        
        # Validate the token
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience="account",  # Keycloak default audience
            issuer=f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}",
            options={
                "verify_aud": False,  # Keycloak has different audience handling
                "verify_iss": True,
                "verify_exp": True,
                "require_exp": True
            }
        )
        
        return payload
        
    except JWTError as e:
        logger.warning(f"Token validation failed: {e}")
        raise


def get_service_token(target_audience: str) -> str:
    """
    Get a service-to-service token using client credentials.
    Zero Trust: Service A authenticates to Service B with its own identity.
    """
    cache_key = f"{KEYCLOAK_CLIENT_ID}:{target_audience}"
    
    # Check cache first
    if cache_key in service_token_cache:
        logger.debug(f"Using cached service token for {target_audience}")
        return service_token_cache[cache_key]
    
    try:
        token_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
        
        # Client credentials grant
        data = {
            "grant_type": "client_credentials",
            "client_id": KEYCLOAK_CLIENT_ID,
            "client_secret": KEYCLOAK_CLIENT_SECRET,
            "scope": "openid"
        }
        
        response = requests.post(token_url, data=data, timeout=10)
        response.raise_for_status()
        
        token_response = response.json()
        access_token = token_response["access_token"]
        
        # Cache the token
        service_token_cache[cache_key] = access_token
        
        logger.info(f"Obtained service token for calling {target_audience}")
        return access_token
        
    except Exception as e:
        logger.error(f"Failed to get service token: {e}")
        raise


# ============================================
# Authentication Decorator
# ============================================
def require_auth(f):
    """
    Decorator to enforce authentication on endpoints.
    Zero Trust: Never trust, always verify.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Get correlation ID for tracing
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        g.correlation_id = correlation_id
        
        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization", "")
        
        if not auth_header.startswith("Bearer "):
            logger.warning(f"[{correlation_id}] Missing or invalid Authorization header")
            return jsonify({
                "error": "unauthorized",
                "message": "Missing or invalid Authorization header",
                "correlation_id": correlation_id
            }), 401
        
        token = auth_header.split(" ")[1]
        
        try:
            # Validate the token
            payload = validate_token(token)
            
            # Store user info in request context
            g.user = {
                "sub": payload.get("sub"),
                "username": payload.get("preferred_username"),
                "email": payload.get("email"),
                "roles": payload.get("realm_access", {}).get("roles", []),
                "client_roles": payload.get("resource_access", {})
            }
            
            logger.info(f"[{correlation_id}] Authenticated user: {g.user['username']}")
            
        except Exception as e:
            logger.warning(f"[{correlation_id}] Authentication failed: {e}")
            return jsonify({
                "error": "unauthorized",
                "message": "Invalid or expired token",
                "correlation_id": correlation_id
            }), 401
        
        return f(*args, **kwargs)
    
    return decorated


# ============================================
# API-to-API Call Helper
# ============================================
def call_service_b(endpoint: str, method: str = "GET", data: dict = None) -> dict:
    """
    Make an authenticated call to Service B.
    Zero Trust: Service-to-service calls require authentication.
    """
    correlation_id = getattr(g, 'correlation_id', str(uuid.uuid4()))
    
    try:
        # Get service token
        service_token = get_service_token(SERVICE_B_AUDIENCE)
        
        # Prepare headers with Zero Trust requirements
        headers = {
            "Authorization": f"Bearer {service_token}",
            "Content-Type": "application/json",
            "X-Correlation-ID": correlation_id,
            "X-Calling-Service": SERVICE_NAME,
            "X-Original-User": getattr(g, 'user', {}).get('username', 'unknown')
        }
        
        url = f"{SERVICE_B_URL}{endpoint}"
        
        logger.info(f"[{correlation_id}] Calling Service B: {method} {url}")
        
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=data, timeout=10)
        elif method == "PUT":
            response = requests.put(url, headers=headers, json=data, timeout=10)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        response.raise_for_status()
        return response.json()
        
    except requests.exceptions.RequestException as e:
        logger.error(f"[{correlation_id}] Service B call failed: {e}")
        raise


# ============================================
# API Endpoints
# ============================================
@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint - no auth required."""
    return jsonify({
        "status": "healthy",
        "service": SERVICE_NAME,
        "timestamp": datetime.utcnow().isoformat()
    })


@app.route("/api/v1/orders", methods=["GET"])
@require_auth
def get_orders():
    """
    Get user's orders.
    Zero Trust: Only return orders belonging to authenticated user.
    """
    correlation_id = g.correlation_id
    username = g.user["username"]
    
    # Filter orders by user (Zero Trust: data isolation)
    user_orders = [
        order for order in ORDERS.values()
        if order["user_id"] == username
    ]
    
    logger.info(f"[{correlation_id}] Returning {len(user_orders)} orders for user {username}")
    
    return jsonify({
        "orders": user_orders,
        "count": len(user_orders),
        "correlation_id": correlation_id
    })


@app.route("/api/v1/orders/<order_id>", methods=["GET"])
@require_auth
def get_order(order_id):
    """
    Get a specific order with inventory information from Service B.
    Demonstrates API-to-API communication.
    """
    correlation_id = g.correlation_id
    username = g.user["username"]
    
    # Get order
    order = ORDERS.get(order_id)
    
    if not order:
        return jsonify({
            "error": "not_found",
            "message": f"Order {order_id} not found",
            "correlation_id": correlation_id
        }), 404
    
    # Zero Trust: Verify user owns this order
    if order["user_id"] != username:
        logger.warning(f"[{correlation_id}] User {username} attempted to access order {order_id} belonging to {order['user_id']}")
        return jsonify({
            "error": "forbidden",
            "message": "You don't have permission to access this order",
            "correlation_id": correlation_id
        }), 403
    
    # Enrich order with inventory data from Service B (API-to-API call)
    try:
        product_ids = [item["product_id"] for item in order["items"]]
        inventory_data = call_service_b(f"/api/v1/inventory?products={','.join(product_ids)}")
        
        # Merge inventory info into order items
        inventory_map = {item["product_id"]: item for item in inventory_data.get("items", [])}
        
        enriched_items = []
        for item in order["items"]:
            enriched_item = {**item}
            if item["product_id"] in inventory_map:
                inv = inventory_map[item["product_id"]]
                enriched_item["product_name"] = inv.get("name")
                enriched_item["in_stock"] = inv.get("quantity", 0) > 0
                enriched_item["available_quantity"] = inv.get("quantity", 0)
            enriched_items.append(enriched_item)
        
        order = {**order, "items": enriched_items, "inventory_checked": True}
        
    except Exception as e:
        logger.warning(f"[{correlation_id}] Failed to fetch inventory: {e}")
        order = {**order, "inventory_checked": False, "inventory_error": str(e)}
    
    logger.info(f"[{correlation_id}] Returning order {order_id} for user {username}")
    
    return jsonify({
        "order": order,
        "correlation_id": correlation_id
    })


@app.route("/api/v1/orders", methods=["POST"])
@require_auth
def create_order():
    """
    Create a new order.
    Validates inventory with Service B before creating.
    """
    correlation_id = g.correlation_id
    username = g.user["username"]
    
    data = request.get_json()
    
    if not data or "items" not in data:
        return jsonify({
            "error": "bad_request",
            "message": "Request must include 'items' array",
            "correlation_id": correlation_id
        }), 400
    
    # Validate inventory with Service B (API-to-API)
    try:
        for item in data["items"]:
            # Check if product is available
            check_result = call_service_b(
                "/api/v1/inventory/check",
                method="POST",
                data={
                    "product_id": item["product_id"],
                    "quantity": item["quantity"]
                }
            )
            
            if not check_result.get("available"):
                return jsonify({
                    "error": "insufficient_inventory",
                    "message": f"Product {item['product_id']} has insufficient inventory",
                    "available": check_result.get("available_quantity", 0),
                    "correlation_id": correlation_id
                }), 409
                
    except Exception as e:
        logger.error(f"[{correlation_id}] Inventory check failed: {e}")
        return jsonify({
            "error": "service_unavailable",
            "message": "Unable to verify inventory",
            "correlation_id": correlation_id
        }), 503
    
    # Create order
    order_id = f"ORD-{str(uuid.uuid4())[:8].upper()}"
    total = sum(item["quantity"] * item["price"] for item in data["items"])
    
    new_order = {
        "id": order_id,
        "user_id": username,
        "items": data["items"],
        "status": "pending",
        "total": round(total, 2),
        "created_at": datetime.utcnow().isoformat()
    }
    
    ORDERS[order_id] = new_order
    
    # Reserve inventory with Service B
    try:
        call_service_b(
            "/api/v1/inventory/reserve",
            method="POST",
            data={
                "order_id": order_id,
                "items": data["items"]
            }
        )
    except Exception as e:
        logger.warning(f"[{correlation_id}] Failed to reserve inventory: {e}")
    
    logger.info(f"[{correlation_id}] Created order {order_id} for user {username}")
    
    return jsonify({
        "order": new_order,
        "message": "Order created successfully",
        "correlation_id": correlation_id
    }), 201


@app.route("/api/v1/user/profile", methods=["GET"])
@require_auth
def get_profile():
    """Return current user's profile from token claims."""
    return jsonify({
        "user": g.user,
        "correlation_id": g.correlation_id
    })


# ============================================
# Error Handlers
# ============================================
@app.errorhandler(Exception)
def handle_exception(e):
    correlation_id = getattr(g, 'correlation_id', 'unknown')
    logger.error(f"[{correlation_id}] Unhandled exception: {e}")
    return jsonify({
        "error": "internal_error",
        "message": "An unexpected error occurred",
        "correlation_id": correlation_id
    }), 500


# ============================================
# Main
# ============================================
if __name__ == "__main__":
    logger.info(f"Starting {SERVICE_NAME} on port {PORT}")
    logger.info(f"Keycloak URL: {KEYCLOAK_URL}")
    logger.info(f"Service B URL: {SERVICE_B_URL}")
    app.run(host="0.0.0.0", port=PORT, debug=True)
