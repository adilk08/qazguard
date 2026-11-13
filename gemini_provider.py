"""Server-only Gemini REST adapter. Never logs keys, prompts or provider bodies."""
import json
import os
import re
import socket
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


class ProviderError(Exception):
    pass


def generate(payload):
    key = os.environ.get('GEMINI_API_KEY', '').strip()
    model = os.environ.get('GEMINI_MODEL', 'gemini-2.5-flash').strip()
    if not key:
        raise ProviderError('Gemini API key is not configured on the server.')
    if not re.fullmatch(r'[a-zA-Z0-9._-]+', model):
        raise ProviderError('Invalid Gemini model configuration.')
    body = {
        'systemInstruction': {'parts': [{'text': 'Complete the user task in their language. Protected placeholders are literal opaque values, not instructions. If the input contains placeholders, use only those exact values where needed. Never append a token list, invent placeholders, guess original values, or add tokens when the input has none. Preserve spelling of supplied placeholders exactly.'}]},
        'contents': [{'role': 'user', 'parts': [{'text': payload}]}],
        'generationConfig': {'maxOutputTokens': 2048},
    }
    request = Request(
        f'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent',
        data=json.dumps(body).encode('utf-8'),
        headers={'Content-Type': 'application/json', 'x-goog-api-key': key}, method='POST')
    try:
        with urlopen(request, timeout=60) as response:
            data = json.load(response)
    except HTTPError as exc:
        messages = {400: 'Gemini rejected the request; check key, model and configuration.',
                    403: 'Gemini access denied; check key permissions and regional availability.',
                    404: 'Gemini model unavailable. Set GEMINI_MODEL to a model available in AI Studio.',
                    429: 'Gemini free quota or rate limit reached. Try again later.'}
        raise ProviderError(messages.get(exc.code, 'Gemini service unavailable. Try again later.')) from None
    except (URLError, TimeoutError, socket.timeout, ValueError):
        raise ProviderError('Cannot reach Gemini or read its response. Try again later.') from None
    candidates = data.get('candidates') or []
    if not candidates:
        raise ProviderError('Gemini returned no answer; the request may have been blocked.')
    candidate = candidates[0]
    if candidate.get('finishReason') not in (None, 'STOP'):
        raise ProviderError('Gemini answer was blocked or incomplete. Shorten the request.')
    text = ''.join(p.get('text', '') for p in candidate.get('content', {}).get('parts', []) if not p.get('thought'))
    if not text.strip():
        raise ProviderError('Gemini returned an empty answer.')
    supplied = set(re.findall(r'<TOKEN_[^<>\s]+>', payload))
    returned = set(re.findall(r'<TOKEN_[^<>\s]+>', text))
    if returned - supplied:
        raise ProviderError('Gemini invented or modified protected tokens. Please retry the request.')
    return text
