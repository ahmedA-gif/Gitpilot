"""Bounded trusted-provider HTTP access with explicit upstream failures."""
import asyncio
import copy
import time
from urllib.parse import urlparse, urljoin
import httpx

ALLOWED_HOSTS = {'api.github.com', 'pypi.org', 'api.osv.dev', 'www.cisa.gov'}
_CACHE: dict[str, tuple[float, object]] = {}
_semaphore = asyncio.Semaphore(6)

class ProviderError(ValueError):
    pass

async def request_json(url: str, *, method: str = 'GET', payload=None, headers=None, ttl: int = 300):
    if urlparse(url).scheme != 'https' or urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ProviderError('Provider URL is not allowed')
    import json
    # Cache identities cannot cross different GitHub credential contexts.
    import hashlib
    identity = hashlib.sha256((headers or {}).get('Authorization', '').encode()).hexdigest()
    key = method + url + identity + json.dumps(payload, sort_keys=True)
    now = time.monotonic()
    if key in _CACHE and _CACHE[key][0] > now:
        return copy.deepcopy(_CACHE[key][1])
    async with _semaphore:
        try:
            async with httpx.AsyncClient(timeout=25, follow_redirects=False) as client:
                response = await client.request(method, url, json=payload, headers=headers or {})
                # Renamed/transferred repositories redirect inside the GitHub API.
                # Never forward credentials to another origin.
                for _ in range(3):
                    if response.status_code not in (301, 302, 307, 308):
                        break
                    target = urljoin(str(response.url), response.headers.get('location', ''))
                    parsed = urlparse(target)
                    if urlparse(url).hostname != 'api.github.com' or parsed.scheme != 'https' or parsed.netloc != 'api.github.com':
                        raise ProviderError('The provider returned an unsupported redirect. Use the repository’s current GitHub link.')
                    response = await client.request(method, target, json=payload, headers=headers or {})
                if 300 <= response.status_code < 400:
                    raise ProviderError('The repository redirected too many times. Use its current GitHub link.')
                if response.status_code in (403, 429):
                    provider = 'GitHub' if urlparse(url).hostname == 'api.github.com' else urlparse(url).hostname
                    raise ProviderError(f'{provider} is temporarily limiting requests or denying access. Try again later.' + (' A server-side GitHub token can increase the request allowance.' if provider == 'GitHub' else ''))
                if response.status_code == 404 and urlparse(url).hostname == 'api.github.com':
                    raise ProviderError('GitHub could not find this repository or resource. Check the spelling and make sure the repository is public.')
                if response.status_code == 409 and urlparse(url).hostname == 'api.github.com':
                    raise ProviderError('This repository has no commits yet, so its files and history cannot be checked.')
                if response.status_code >= 400:
                    raise ProviderError(f'{urlparse(url).hostname}: HTTP {response.status_code}')
                if len(response.content) > 16_000_000:
                    raise ProviderError('Provider response exceeded size limit')
                try:
                    result = response.json()
                except ValueError:
                    raise ProviderError('The provider returned an unreadable response. Please try again.') from None
        except httpx.HTTPError as exc:
            raise ProviderError(f'{urlparse(url).hostname}: network request failed ({type(exc).__name__})') from None
    if len(_CACHE) >= 256:
        _CACHE.pop(next(iter(_CACHE)))
    _CACHE[key] = (now + ttl, result)
    return copy.deepcopy(result)
