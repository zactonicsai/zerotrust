"""
Service B - Inventory Service
=============================
Zero Trust Implementation:
1. INTERNAL SERVICE ONLY - not directly accessible by users
2. Validates service-to-service tokens
3. Verifies caller identity against allow list
4. Implements fine-grained authorization
"""

import os
import logging
import uuid
from functools import wraps
from datetime import datetime

import requests
from flask import Flask, jsonify, request, g
from jose import jwt, JWTError
from cachetools import TTLCache

# ============================================
# Configuration
# ============================================
app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Environment configuration
SERVICE_NAME = os.getenv("SERVICE_NAME", "inventory-service")
PORT = int(os.getenv("PORT", 5002))
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080/auth")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "zero-trust-demo")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "inventory-service")

# Zero Trust: Explicit allow list of services that can call this API
ALLOWED_CALLERS = os.getenv("ALLOWED_CALLERS", "orders-service").split(",")

# JWKS cache
jwks_cache = {"keys": None, "fetched_at": None}

# ============================================
# Mock Inventory Data
# ============================================
INVENTORY = {
    "PROD-001": {
        "product_id": "PROD-001",
        "name": "Wireless Mouse",
        "quantity": 150,
        "price": 29.99,
        "reserved": 0
    },
    "PROD-002": {
        "product_id": "PROD-002",
        "name": "Mechanical Keyboard",
        "quantity": 75,
        "price": 49.99,
        "reserved": 0
    },
    "PROD-003": {
        "product_id": "PROD-003",
        "name": "USB-C Hub",
        "quantity": 200,
        "price": 15.00,
        "reserved": 0
    },
    "PROD-004": {
        "product_id": "PROD-004",
        "name": "Monitor Stand",
        "quantity": 50,
        "price": 79.99,
        "reserved": 5
    },
    "PROD-005": {
        "product_id": "PROD-005",
        "name": "Webcam HD",
        "quantity": 0,
        "price": 89.99,
        "reserved": 0
    }
}

# Track reservations
RESERVATIONS = {}

# ============================================
# JWT / Keycloak Utilities
# ============================================
def get_keycloak_public_keys():
    """Fetch JWKS from Keycloak for token validation."""
    global jwks_cache
    
    if jwks_cache["keys"] and jwks_cache["fetched_at"]:
        age = (datetime.now() - jwks_cache["fetched_at"]).seconds
        if age < 300:
            return jwks_cache["keys"]
    
    try:
        jwks_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
        response = requests.get(jwks_url, timeout=10)
        response.raise_for_status()
        jwks_cache["keys"] = response.json()
        jwks_cache["fetched_at"] = datetime.now()
        logger.info(f"Fetched JWKS from Keycloak")
        return jwks_cache["keys"]
    except Exception as e:
        logger.error(f"Failed to fetch JWKS: {e}")
        if jwks_cache["keys"]:
            return jwks_cache["keys"]
        raise


def validate_service_token(token: str) -> dict:
    """
    Validate service-to-service JWT token.
    Zero Trust: Verify the calling service's identity.
    """
    try:
        jwks = get_keycloak_public_keys()
        
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        
        rsa_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                rsa_key = key
                break
        
        if not rsa_key:
            raise JWTError("Unable to find matching key")
        
        # Validate token
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            issuer=f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}",
            options={
                "verify_aud": False,
                "verify_iss": True,
                "verify_exp": True,
                "require_exp": True
            }
        )
        
        return payload
        
    except JWTError as e:
        logger.warning(f"Service token validation failed: {e}")
        raise


# ============================================
# Service-to-Service Authentication Decorator
# ============================================
def require_service_auth(f):
    """
    Decorator to enforce service-to-service authentication.
    Zero Trust: Only allow calls from explicitly authorized services.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        g.correlation_id = correlation_id
        
        calling_service = request.headers.get("X-Calling-Service", "unknown")
        original_user = request.headers.get("X-Original-User", "unknown")
        
        # Extract token
        auth_header = request.headers.get("Authorization", "")
        
        if not auth_header.startswith("Bearer "):
            logger.warning(f"[{correlation_id}] Missing Authorization header from {calling_service}")
            return jsonify({
                "error": "unauthorized",
                "message": "Missing or invalid Authorization header",
                "correlation_id": correlation_id
            }), 401
        
        token = auth_header.split(" ")[1]
        
        try:
            # Validate the service token
            payload = validate_service_token(token)
            
            # Extract service identity
            # For client credentials, the 'azp' (authorized party) or 'client_id' identifies the caller
            service_id = payload.get("azp") or payload.get("client_id")
            
            # Zero Trust: Verify caller is in allow list
            if service_id not in ALLOWED_CALLERS:
                logger.warning(
                    f"[{correlation_id}] Unauthorized caller: {service_id}. "
                    f"Allowed: {ALLOWED_CALLERS}"
                )
                return jsonify({
                    "error": "forbidden",
                    "message": f"Service {service_id} is not authorized to call this API",
                    "correlation_id": correlation_id
                }), 403
            
            # Store caller info in request context
            g.caller = {
                "service_id": service_id,
                "original_user": original_user,
                "token_claims": payload
            }
            
            logger.info(
                f"[{correlation_id}] Authenticated service call: "
                f"{service_id} (on behalf of: {original_user})"
            )
            
        except Exception as e:
            logger.warning(f"[{correlation_id}] Service authentication failed: {e}")
            return jsonify({
                "error": "unauthorized",
                "message": "Invalid or expired service token",
                "correlation_id": correlation_id
            }), 401
        
        return f(*args, **kwargs)
    
    return decorated


# ============================================
# Audit Logging
# ============================================
def audit_log(action: str, resource: str, details: dict = None):
    """
    Zero Trust: Log all access for audit trail.
    """
    correlation_id = getattr(g, 'correlation_id', 'unknown')
    caller = getattr(g, 'caller', {})
    
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "correlation_id": correlation_id,
        "action": action,
        "resource": resource,
        "caller_service": caller.get("service_id", "unknown"),
        "original_user": caller.get("original_user", "unknown"),
        "details": details or {}
    }
    
    logger.info(f"AUDIT: {log_entry}")


# ============================================
# API Endpoints
# ============================================
@app.route("/health", methods=["GET"])
def health():
    """Health check - no auth required."""
    return jsonify({
        "status": "healthy",
        "service": SERVICE_NAME,
        "timestamp": datetime.utcnow().isoformat()
    })


@app.route("/api/v1/inventory", methods=["GET"])
@require_service_auth
def get_inventory():
    """
    Get inventory for specified products.
    Zero Trust: Only authorized services can access inventory data.
    """
    correlation_id = g.correlation_id
    
    # Get product filter from query params
    products_param = request.args.get("products", "")
    
    if products_param:
        product_ids = [p.strip() for p in products_param.split(",")]
        items = [
            INVENTORY[pid] for pid in product_ids
            if pid in INVENTORY
        ]
    else:
        items = list(INVENTORY.values())
    
    # Calculate available quantity (total - reserved)
    response_items = []
    for item in items:
        response_items.append({
            **item,
            "available_quantity": item["quantity"] - item["reserved"]
        })
    
    audit_log("READ", "inventory", {"product_count": len(response_items)})
    
    return jsonify({
        "items": response_items,
        "count": len(response_items),
        "correlation_id": correlation_id
    })


@app.route("/api/v1/inventory/<product_id>", methods=["GET"])
@require_service_auth
def get_product_inventory(product_id):
    """Get inventory for a single product."""
    correlation_id = g.correlation_id
    
    if product_id not in INVENTORY:
        return jsonify({
            "error": "not_found",
            "message": f"Product {product_id} not found",
            "correlation_id": correlation_id
        }), 404
    
    item = INVENTORY[product_id]
    
    audit_log("READ", f"inventory/{product_id}")
    
    return jsonify({
        "item": {
            **item,
            "available_quantity": item["quantity"] - item["reserved"]
        },
        "correlation_id": correlation_id
    })


@app.route("/api/v1/inventory/check", methods=["POST"])
@require_service_auth
def check_availability():
    """
    Check if requested quantity is available.
    Zero Trust: Validate all inputs.
    """
    correlation_id = g.correlation_id
    
    data = request.get_json()
    
    if not data or "product_id" not in data or "quantity" not in data:
        return jsonify({
            "error": "bad_request",
            "message": "Request must include 'product_id' and 'quantity'",
            "correlation_id": correlation_id
        }), 400
    
    product_id = data["product_id"]
    requested_quantity = data["quantity"]
    
    if product_id not in INVENTORY:
        return jsonify({
            "error": "not_found",
            "message": f"Product {product_id} not found",
            "correlation_id": correlation_id
        }), 404
    
    item = INVENTORY[product_id]
    available = item["quantity"] - item["reserved"]
    is_available = available >= requested_quantity
    
    audit_log("CHECK", f"inventory/{product_id}", {
        "requested": requested_quantity,
        "available": available,
        "result": is_available
    })
    
    return jsonify({
        "product_id": product_id,
        "requested_quantity": requested_quantity,
        "available_quantity": available,
        "available": is_available,
        "correlation_id": correlation_id
    })


@app.route("/api/v1/inventory/reserve", methods=["POST"])
@require_service_auth
def reserve_inventory():
    """
    Reserve inventory for an order.
    Zero Trust: Validate caller permissions and inputs.
    """
    correlation_id = g.correlation_id
    
    data = request.get_json()
    
    if not data or "order_id" not in data or "items" not in data:
        return jsonify({
            "error": "bad_request",
            "message": "Request must include 'order_id' and 'items'",
            "correlation_id": correlation_id
        }), 400
    
    order_id = data["order_id"]
    items = data["items"]
    
    # Check all items first
    for item in items:
        product_id = item["product_id"]
        quantity = item["quantity"]
        
        if product_id not in INVENTORY:
            return jsonify({
                "error": "not_found",
                "message": f"Product {product_id} not found",
                "correlation_id": correlation_id
            }), 404
        
        inv = INVENTORY[product_id]
        available = inv["quantity"] - inv["reserved"]
        
        if available < quantity:
            return jsonify({
                "error": "insufficient_inventory",
                "message": f"Insufficient inventory for {product_id}",
                "available": available,
                "requested": quantity,
                "correlation_id": correlation_id
            }), 409
    
    # Reserve all items
    reserved_items = []
    for item in items:
        product_id = item["product_id"]
        quantity = item["quantity"]
        
        INVENTORY[product_id]["reserved"] += quantity
        reserved_items.append({
            "product_id": product_id,
            "reserved_quantity": quantity
        })
    
    # Track reservation
    RESERVATIONS[order_id] = {
        "items": reserved_items,
        "created_at": datetime.utcnow().isoformat(),
        "caller_service": g.caller["service_id"]
    }
    
    audit_log("RESERVE", f"inventory/reservation/{order_id}", {
        "items": reserved_items
    })
    
    return jsonify({
        "order_id": order_id,
        "reserved": True,
        "items": reserved_items,
        "correlation_id": correlation_id
    }), 201


@app.route("/api/v1/inventory/release/<order_id>", methods=["POST"])
@require_service_auth
def release_reservation(order_id):
    """Release a reservation (e.g., order cancelled)."""
    correlation_id = g.correlation_id
    
    if order_id not in RESERVATIONS:
        return jsonify({
            "error": "not_found",
            "message": f"Reservation {order_id} not found",
            "correlation_id": correlation_id
        }), 404
    
    reservation = RESERVATIONS[order_id]
    
    # Release reserved quantities
    for item in reservation["items"]:
        product_id = item["product_id"]
        quantity = item["reserved_quantity"]
        
        if product_id in INVENTORY:
            INVENTORY[product_id]["reserved"] = max(
                0, INVENTORY[product_id]["reserved"] - quantity
            )
    
    del RESERVATIONS[order_id]
    
    audit_log("RELEASE", f"inventory/reservation/{order_id}")
    
    return jsonify({
        "order_id": order_id,
        "released": True,
        "correlation_id": correlation_id
    })


# ============================================
# Internal Metrics Endpoint
# ============================================
@app.route("/internal/metrics", methods=["GET"])
@require_service_auth
def get_metrics():
    """Internal metrics - only for authorized services."""
    total_inventory = sum(item["quantity"] for item in INVENTORY.values())
    total_reserved = sum(item["reserved"] for item in INVENTORY.values())
    
    return jsonify({
        "service": SERVICE_NAME,
        "metrics": {
            "total_products": len(INVENTORY),
            "total_inventory": total_inventory,
            "total_reserved": total_reserved,
            "active_reservations": len(RESERVATIONS)
        },
        "timestamp": datetime.utcnow().isoformat()
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
    logger.info(f"Allowed callers: {ALLOWED_CALLERS}")
    app.run(host="0.0.0.0", port=PORT, debug=True)
