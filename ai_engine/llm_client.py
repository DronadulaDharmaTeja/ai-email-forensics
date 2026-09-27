"""
Central OpenAI-compatible LLM client for the Email Forensics project.

Providers supported:
    NVIDIA
        https://integrate.api.nvidia.com/v1

    PAIR (Personal AI Router)
        http://127.0.0.1:11434/v1

The rest of the project should call only:
    generate_response(...)
    test_connection()

The provider is selected through .env:
    AI_PROVIDER=PAIR
or:
    AI_PROVIDER=NVIDIA

PAIR configuration:
    PAIR_BASE_URL=http://127.0.0.1:11434/v1
    PAIR_MODEL_NAME=nemotron-3-nano:4b

NVIDIA configuration:
    NVIDIA_API_KEY=...
    NVIDIA_MODEL_NAME=nvidia/nemotron-3.5-lightning-30b-a3b
    NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1

No API key is required for the local PAIR provider.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Union

from dotenv import load_dotenv
from openai import OpenAI


# ---------------------------------------------------------------------
# PROJECT CONFIGURATION
# ---------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(ENV_FILE)


# ---------------------------------------------------------------------
# ENVIRONMENT VARIABLES
# ---------------------------------------------------------------------

NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")

NVIDIA_MODEL_NAME = os.getenv(
    "NVIDIA_MODEL_NAME",
    "nvidia/nemotron-3.5-lightning-30b-a3b",
).strip()

NVIDIA_BASE_URL = os.getenv(
    "NVIDIA_BASE_URL",
    "https://integrate.api.nvidia.com/v1",
).strip()

AI_PROVIDER = os.getenv(
    "AI_PROVIDER",
    "NVIDIA",
).strip().upper()

PAIR_BASE_URL = os.getenv(
    "PAIR_BASE_URL",
    "http://127.0.0.1:11434/v1",
).strip()

PAIR_MODEL_NAME = os.getenv(
    "PAIR_MODEL_NAME",
    "nemotron-3-nano:4b",
).strip()

# A larger local timeout is useful for forensic prompts running through
# a local model. It is configurable without changing Python code.
try:
    REQUEST_TIMEOUT = float(
        os.getenv(
            "LLM_REQUEST_TIMEOUT",
            "600" if AI_PROVIDER == "PAIR" else "300",
        )
    )
except ValueError as exc:
    raise RuntimeError(
        "LLM_REQUEST_TIMEOUT must be a positive number."
    ) from exc

if REQUEST_TIMEOUT <= 0:
    raise RuntimeError(
        "LLM_REQUEST_TIMEOUT must be greater than 0."
    )

SUPPORTED_PROVIDERS = {"NVIDIA", "PAIR"}

if AI_PROVIDER not in SUPPORTED_PROVIDERS:
    raise RuntimeError(
        f"Unsupported AI_PROVIDER '{AI_PROVIDER}'. "
        f"Expected one of: {', '.join(sorted(SUPPORTED_PROVIDERS))}."
    )


# ---------------------------------------------------------------------
# ACTIVE PROVIDER CONFIGURATION
# ---------------------------------------------------------------------

if AI_PROVIDER == "PAIR":
    ACTIVE_API_KEY = "local"
    ACTIVE_BASE_URL = PAIR_BASE_URL
    ACTIVE_MODEL_NAME = PAIR_MODEL_NAME
else:
    if not NVIDIA_API_KEY:
        raise RuntimeError(
            "NVIDIA_API_KEY is not configured in the project .env file."
        )

    ACTIVE_API_KEY = NVIDIA_API_KEY
    ACTIVE_BASE_URL = NVIDIA_BASE_URL
    ACTIVE_MODEL_NAME = NVIDIA_MODEL_NAME

if not ACTIVE_BASE_URL:
    raise RuntimeError("Active LLM base URL is empty.")

if not ACTIVE_MODEL_NAME:
    raise RuntimeError("Active LLM model name is empty.")


# ---------------------------------------------------------------------
# OPENAI-COMPATIBLE CLIENT
# ---------------------------------------------------------------------

client = OpenAI(
    base_url=ACTIVE_BASE_URL,
    api_key=ACTIVE_API_KEY,
    timeout=REQUEST_TIMEOUT,
)


# ---------------------------------------------------------------------
# JSON PARSER
# ---------------------------------------------------------------------

def _parse_json_response(text: str) -> Dict[str, Any]:
    """
    Convert an LLM JSON response into a Python dictionary.

    Handles:
        1. Pure JSON
        2. Markdown JSON fences
        3. Extra text before/after a JSON object
        4. Balanced JSON-object extraction
    """

    if not isinstance(text, str):
        raise TypeError("JSON response must be a string before parsing.")

    text = text.strip()

    if not text:
        raise ValueError("LLM returned an empty response.")

    # Direct JSON.
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, TypeError):
        pass

    # Remove markdown code fences.
    cleaned = re.sub(
        r"```(?:json)?",
        "",
        text,
        flags=re.IGNORECASE,
    )
    cleaned = cleaned.replace("```", "").strip()

    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, TypeError):
        pass

    # Balanced JSON-object extraction.
    start = cleaned.find("{")
    if start == -1:
        raise ValueError(
            "LLM response did not contain a JSON object."
        )

    depth = 0
    in_string = False
    escaped = False

    for index in range(start, len(cleaned)):
        char = cleaned[index]

        if escaped:
            escaped = False
            continue

        if char == "\\" and in_string:
            escaped = True
            continue

        if char == '"':
            in_string = not in_string
            continue

        if in_string:
            continue

        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1

            if depth == 0:
                candidate = cleaned[start : index + 1]

                try:
                    parsed = json.loads(candidate)
                except (json.JSONDecodeError, TypeError) as exc:
                    raise ValueError(
                        "LLM response contained an invalid JSON object."
                    ) from exc

                if isinstance(parsed, dict):
                    return parsed

                raise ValueError(
                    "Extracted JSON value is not an object."
                )

    raise ValueError(
        "LLM response did not contain valid JSON."
    )


# Backward-compatible helper used by older project code/tests.
def _extract_json_object(text: Any) -> Dict[str, Any]:
    """Extract and return one JSON object from an LLM response."""

    if isinstance(text, dict):
        return text

    if text is None:
        raise ValueError("LLM response was empty.")

    return _parse_json_response(str(text))


# ---------------------------------------------------------------------
# REQUEST BUILDING
# ---------------------------------------------------------------------

def _build_request_kwargs(
    prompt: str,
    json_mode: bool,
    max_tokens: int,
    temperature: float,
) -> Dict[str, Any]:
    """Build an OpenAI-compatible request for the active provider."""

    request_kwargs: Dict[str, Any] = {
        "model": ACTIVE_MODEL_NAME,
        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }

    if json_mode:
        request_kwargs["response_format"] = {
            "type": "json_object",
        }

    if AI_PROVIDER == "PAIR":
        # Ollama/PAIR supports this parameter for Nemotron to disable
        # reasoning when a fast, structured response is required.
        request_kwargs["extra_body"] = {
            "think": False,
        }
    else:
        # NVIDIA's hosted endpoint uses this provider-specific structure.
        request_kwargs["extra_body"] = {
            "chat_template_kwargs": {
                "enable_thinking": False,
            }
        }

    return request_kwargs


# ---------------------------------------------------------------------
# API CALL
# ---------------------------------------------------------------------

def _call_model(request_kwargs: Dict[str, Any]):
    """Call the active model with one controlled retry for transient errors."""

    try:
        return client.chat.completions.create(**request_kwargs)
    except Exception as exc:
        # Keep compatibility across OpenAI Python client versions without
        # importing version-specific exception classes.
        retryable = {
            "APITimeoutError",
            "APIConnectionError",
            "RateLimitError",
            "InternalServerError",
        }

        if exc.__class__.__name__ not in retryable:
            raise

        return client.chat.completions.create(**request_kwargs)


# ---------------------------------------------------------------------
# MAIN GENERATION FUNCTION
# ---------------------------------------------------------------------

def generate_response(
    prompt: str,
    json_mode: bool = False,
    max_tokens: int = 4096,
    temperature: float = 0.2,
) -> Union[str, Dict[str, Any]]:
    """
    Generate a response through the configured provider.

    When AI_PROVIDER=PAIR, requests are sent to Personal AI Router.
    When AI_PROVIDER=NVIDIA, requests are sent to NVIDIA's hosted API.
    """

    if not isinstance(prompt, str):
        raise TypeError("prompt must be a string.")

    if not prompt.strip():
        raise ValueError("prompt cannot be empty.")

    if not isinstance(max_tokens, int) or max_tokens <= 0:
        raise ValueError("max_tokens must be a positive integer.")

    if not isinstance(temperature, (int, float)):
        raise TypeError("temperature must be numeric.")

    if not 0.0 <= float(temperature) <= 2.0:
        raise ValueError("temperature must be between 0.0 and 2.0.")

    request_kwargs = _build_request_kwargs(
        prompt=prompt,
        json_mode=json_mode,
        max_tokens=max_tokens,
        temperature=float(temperature),
    )

    completion = _call_model(request_kwargs)

    if not completion.choices:
        raise RuntimeError(
            f"{AI_PROVIDER} returned no choices."
        )

    message = completion.choices[0].message
    content = message.content

    if content is None or not str(content).strip():
        raise RuntimeError(
            f"{AI_PROVIDER} returned an empty message content."
        )

    content = str(content).strip()

    # Structured JSON response.
    if json_mode:
        try:
            return _parse_json_response(content)
        except ValueError as first_error:
            # One controlled JSON-only retry.
            retry_prompt = (
                prompt
                + "\n\nIMPORTANT: Return exactly ONE valid JSON object. "
                "Do not include markdown, code fences, reasoning, "
                "commentary, or any text outside the JSON object."
            )

            retry_kwargs = _build_request_kwargs(
                prompt=retry_prompt,
                json_mode=True,
                max_tokens=max_tokens,
                temperature=0.0,
            )

            try:
                retry_completion = _call_model(retry_kwargs)
            except Exception as retry_error:
                raise ValueError(
                    "Structured JSON generation failed after retry."
                ) from retry_error

            if not retry_completion.choices:
                raise RuntimeError(
                    f"{AI_PROVIDER} JSON retry returned no choices."
                ) from first_error

            retry_content = retry_completion.choices[0].message.content

            if retry_content is None or not str(retry_content).strip():
                raise RuntimeError(
                    f"{AI_PROVIDER} JSON retry returned empty content."
                ) from first_error

            try:
                return _parse_json_response(str(retry_content))
            except ValueError as retry_error:
                raise ValueError(
                    f"{AI_PROVIDER} returned invalid JSON after retry."
                ) from retry_error

    return content


# ---------------------------------------------------------------------
# CONNECTION TEST
# ---------------------------------------------------------------------

def test_connection() -> Dict[str, Any]:
    """Test the currently configured LLM provider."""

    response = generate_response(
        "Respond with exactly one short sentence confirming "
        "that the email forensics AI engine is online.",
        json_mode=False,
        max_tokens=200,
        temperature=0.0,
    )

    return {
        "status": "CONNECTED",
        "provider": AI_PROVIDER,
        "base_url": ACTIVE_BASE_URL,
        "model": ACTIVE_MODEL_NAME,
        "response": response,
    }


# ---------------------------------------------------------------------
# PUBLIC API
# ---------------------------------------------------------------------

__all__ = [
    "generate_response",
    "test_connection",
    "AI_PROVIDER",
    "ACTIVE_BASE_URL",
    "ACTIVE_MODEL_NAME",
]
