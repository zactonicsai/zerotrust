# Zero Trust Microservices Demo

A complete example demonstrating Zero Trust security architecture with:
- **Keycloak** as the Identity Provider (IdP)
- **Service A (Orders)** - Public-facing API with JWT validation
- **Service B (Inventory)** - Internal API with service-to-service authentication
- **Frontend** - HTML/JS app with OAuth2 PKCE authentication

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ZERO TRUST ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────┐      ①            ┌─────────────┐                           │
│   │          │ ─────────────────▶│             │                           │
│   │  User /  │   Login (PKCE)    │  Keycloak   │  Port 8080               │
│   │ Frontend │ ◀─────────────────│    (IdP)    │                           │
│   │          │   JWT Token       │             │                           │
│   └────┬─────┘  Port 3000        └──────┬──────┘                           │
│        │                                │                                   │
│        │ ② API Call                     │ ③ Validate Token                 │
│        │ + Bearer Token                 │ + Issue Service Token            │
│        ▼                                ▼                                   │
│   ┌─────────────┐            ┌─────────────────────────┐                   │
│   │  Service A  │ ──────────▶│       Service B         │                   │
│   │  (Orders)   │  ④ API-to-API       (Inventory)      │                   │
│   │             │  + Service Token                      │                   │
│   │  Port 5001  │ ◀──────────│        Port 5002        │                   │
│   └─────────────┘   Response └─────────────────────────┘                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Zero Trust Features Demonstrated

### 1. Identity & Authentication
- ✅ OAuth2 Authorization Code flow with PKCE
- ✅ JWT token validation against Keycloak JWKS
- ✅ Service accounts for API-to-API communication
- ✅ Short-lived access tokens (5 minutes)

### 2. Authorization
- ✅ Token-based user authentication
- ✅ Service-to-service allowlist (`ALLOWED_CALLERS`)
- ✅ User-scoped data access (users only see their orders)
- ✅ Role-based access control ready

### 3. Security
- ✅ No implicit trust - all requests validated
- ✅ Correlation IDs for request tracing
- ✅ Audit logging for all operations
- ✅ Non-root container users

### 4. Observability
- ✅ Structured logging
- ✅ Request correlation tracking
- ✅ Original user propagation in service-to-service calls

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Ports 3000, 5001, 5002, 8080 available

### 1. Start the Stack

```bash
cd zero-trust-demo
docker-compose up --build
```

### 2. Wait for Services

Wait ~60 seconds for Keycloak to fully initialize. You can check the logs:

```bash
docker-compose logs -f keycloak
```

Look for: `Running the server in development mode`

### 3. Access the Demo

| Service | URL | Description |
|---------|-----|-------------|
| Frontend | http://localhost:3000 | Demo UI |
| Keycloak Admin | http://localhost:8080/auth/admin | Admin console |
| Service A | http://localhost:5001/health | Orders API |
| Service B | http://localhost:5002/health | Inventory API |

### 4. Test Credentials

| User | Password | Role |
|------|----------|------|
| testuser | testpass123 | user |
| admin | adminpass123 | admin |

**Keycloak Admin:** admin / admin

## Usage Flow

### Frontend → Service A (Client-to-API)

1. Open http://localhost:3000
2. Click "Login with Keycloak"
3. Login with `testuser` / `testpass123`
4. Click "Get My Orders" to fetch orders
5. Click "Get Order Detail" to see API-to-API in action

### API-to-API Flow (Service A → Service B)

When you request order details, Service A:
1. Validates your JWT token
2. Obtains a service token using client credentials
3. Calls Service B's inventory API
4. Enriches the order with inventory data
5. Returns combined response

## API Endpoints

### Service A (Orders) - Port 5001

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | /health | None | Health check |
| GET | /api/v1/orders | User JWT | Get user's orders |
| GET | /api/v1/orders/{id} | User JWT | Get order with inventory |
| POST | /api/v1/orders | User JWT | Create new order |
| GET | /api/v1/user/profile | User JWT | Get user profile |

### Service B (Inventory) - Port 5002

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | /health | None | Health check |
| GET | /api/v1/inventory | Service Token | Get inventory items |
| GET | /api/v1/inventory/{id} | Service Token | Get single item |
| POST | /api/v1/inventory/check | Service Token | Check availability |
| POST | /api/v1/inventory/reserve | Service Token | Reserve inventory |

## Testing with cURL

### Get a User Token

```bash
# Get access token for testuser
TOKEN=$(curl -s -X POST "http://localhost:8080/auth/realms/zero-trust-demo/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=frontend-app" \
  -d "username=testuser" \
  -d "password=testpass123" \
  | jq -r '.access_token')

echo $TOKEN
```

### Call Service A with User Token

```bash
# Get orders
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5001/api/v1/orders | jq

# Get order detail (triggers API-to-API call)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5001/api/v1/orders/ORD-001 | jq
```

### Direct Service-to-Service Call (Simulating Service A)

```bash
# Get service token
SERVICE_TOKEN=$(curl -s -X POST "http://localhost:8080/auth/realms/zero-trust-demo/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=orders-service" \
  -d "client_secret=orders-service-secret" \
  | jq -r '.access_token')

# Call Service B
curl -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H "X-Calling-Service: orders-service" \
  http://localhost:5002/api/v1/inventory | jq
```

### Test Unauthorized Access to Service B

```bash
# Try calling Service B with user token (should fail - 403)
curl -H "Authorization: Bearer $TOKEN" \
  -H "X-Calling-Service: frontend" \
  http://localhost:5002/api/v1/inventory
```

## Keycloak Configuration

The demo pre-configures:

### Realm: `zero-trust-demo`
- Users: testuser, admin
- Clients: frontend-app, orders-service, inventory-service

### Clients

| Client | Type | Flow | Purpose |
|--------|------|------|---------|
| frontend-app | Public | Auth Code + PKCE | User authentication |
| orders-service | Confidential | Client Credentials | Service A identity |
| inventory-service | Confidential | Client Credentials | Service B identity |

## Customization

### Adding More Services

1. Create a new service directory
2. Add to `docker-compose.yml`
3. Register a new client in Keycloak realm
4. Add to `ALLOWED_CALLERS` if needed

### Changing Token Lifetimes

Edit `keycloak/realm-export.json`:
```json
{
  "accessTokenLifespan": 300,  // 5 minutes
  "ssoSessionMaxLifespan": 36000  // 10 hours
}
```

### Adding Custom Scopes

Add to `keycloak/realm-export.json` under `clientScopes`.

## Troubleshooting

### Keycloak not ready

```bash
# Check logs
docker-compose logs keycloak

# Restart if needed
docker-compose restart keycloak
```

### Token validation errors

- Ensure Keycloak is fully started
- Check service URLs match (especially `KEYCLOAK_URL`)
- Verify realm name is correct

### CORS errors

- Check browser console for specific errors
- Verify CORS origins in Service A match frontend URL

### Service B rejecting calls

- Check `ALLOWED_CALLERS` environment variable
- Verify service token has correct `azp` claim
- Check Service B logs for auth errors

## Clean Up

```bash
docker-compose down -v
```

## Security Considerations for Production

This demo is for learning. For production:

1. **Use HTTPS everywhere** - TLS termination at gateway
2. **External Keycloak** - Production-grade IdP setup
3. **Secret management** - Vault, AWS Secrets Manager
4. **mTLS** - Add mutual TLS with service mesh (Istio/Linkerd)
5. **Rate limiting** - Add API gateway with rate limits
6. **Audit logging** - Send to SIEM system
7. **Token rotation** - Implement refresh token rotation
8. **Network policies** - Kubernetes network policies

## License

MIT - Use freely for learning and reference.
