"""Portable, signed scan results for stateless hosting without a database."""
import base64
import hashlib
import hmac
import json
import os
import zlib
from backend.schemas import ScanResult

MAX_REPORT_BYTES = 3_000_000

def secret():
    value = os.getenv('REPORT_SIGNING_SECRET')
    if not value:
        raise ValueError('Report signing is not configured on the server.')
    return value.encode()

def seal(scan: ScanResult) -> str:
    data = json.dumps(scan.model_dump(exclude={'report_token'}), separators=(',', ':')).encode()
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError('This report exceeds the hosted report size limit. Choose fewer scan modules.')
    payload = base64.urlsafe_b64encode(zlib.compress(data)).decode()
    signature = hmac.new(secret(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + '.' + signature

def unseal(token: str) -> ScanResult:
    try:
        payload, signature = token.rsplit('.', 1)
        expected = hmac.new(secret(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        decoder = zlib.decompressobj()
        data = decoder.decompress(base64.urlsafe_b64decode(payload), MAX_REPORT_BYTES + 1)
        if len(data) > MAX_REPORT_BYTES or not decoder.eof:
            raise ValueError
        return ScanResult.model_validate(json.loads(data))
    except (ValueError, TypeError, zlib.error) as exc:
        raise ValueError('This saved report is invalid or was signed by an earlier deployment. Please scan again.') from exc
