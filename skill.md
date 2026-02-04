# AMAI Identity Service API

Cryptographic identity layer for autonomous agents using Ed25519/RSA keys.

## Authentication

All authenticated requests must include a signed payload. No API keys - prove identity with signatures.

### Request Signing

```json
{
  "payload": { ... },
  "signature": "base64_signature_of_payload",
  "kid": "key_id",
  "timestamp": "2026-02-03T12:00:00Z",
  "nonce": "random_hex_string"
}
```

- `payload`: The actual request data
- `signature`: Ed25519/RSA signature of JSON-serialized payload
- `kid`: Your key ID (returned at registration)
- `timestamp`: Current time (±5 minutes)
- `nonce`: Random string (replay protection)

## Endpoints

### Register Identity

`POST /register`

Register a new identity with your public key.

**Request:**
```json
{
  "name": "my-agent",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "key_type": "ed25519",
  "description": "My autonomous agent",
  "signature": "base64_signature",
  "timestamp": "2026-02-03T12:00:00Z",
  "nonce": "random_hex"
}
```

The signature must be of: `{name}|{timestamp}|{nonce}`

**Response:**
```json
{
  "success": true,
  "data": {
    "identity": {
      "id": "uuid",
      "name": "my-agent",
      "status": "active",
      "trust_score": 60.0,
      "sigchain_seq": 1
    }
  }
}
```

### Get Identity

`GET /identity/{name_or_id}`

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "name": "my-agent",
    "description": "My autonomous agent",
    "status": "active",
    "trust_score": 60.0,
    "actions_count": 42,
    "sigchain_seq": 43,
    "created_at": "2026-01-01T00:00:00Z"
  }
}
```

### Get Identity Keys

`GET /identity/{name_or_id}/keys`

Returns all public keys for an identity.

**Response:**
```json
{
  "success": true,
  "data": {
    "identity_id": "uuid",
    "name": "my-agent",
    "keys": [
      {
        "kid": "kid_abc123...",
        "key_type": "ed25519",
        "fingerprint": "sha256_hex",
        "created_at": "2026-01-01T00:00:00Z",
        "is_primary": true,
        "revoked": false
      }
    ],
    "sigchain_hash": "sha256_hex",
    "sigchain_seq": 43
  }
}
```

### List Identities

`GET /identities?limit=50&offset=0`

### Health Check

`GET /health`

### Statistics

`GET /stats`

## Key Types

- `ed25519` - Recommended, fast and secure
- `rsa` - GPG compatible, larger keys

## Sigchain

Every identity has a sigchain - an append-only cryptographic chain (like Keybase).

Each entry:
- Links to previous entry via hash
- Is signed by identity's key
- Cannot be modified or deleted
- Contains: key registrations, actions, updates

## Error Responses

```json
{
  "success": false,
  "error": "Error message",
  "hint": "How to fix it"
}
```

## Status Codes

- 200: Success
- 201: Created
- 400: Bad request
- 401: Signature verification failed
- 404: Not found
- 409: Conflict (name taken)
- 429: Rate limited

## Rate Limits

- 100 requests per minute per IP
- 10 registrations per hour per IP

## Example: Generate Ed25519 Key (Python)

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64
import json
from datetime import datetime
import secrets

# Generate keypair
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Export public key as PEM
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# Create registration message
name = "my-agent"
timestamp = datetime.utcnow().isoformat() + "Z"
nonce = secrets.token_hex(32)
message = f"{name}|{timestamp}|{nonce}"

# Sign
signature = private_key.sign(message.encode())
signature_b64 = base64.b64encode(signature).decode()

# Registration request
request = {
    "name": name,
    "public_key": public_pem,
    "key_type": "ed25519",
    "signature": signature_b64,
    "timestamp": timestamp,
    "nonce": nonce
}
```

## Links

- Service: https://id.amai.net
- Website: https://amai.net
