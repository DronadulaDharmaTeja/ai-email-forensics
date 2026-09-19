"""
Central NVIDIA Nemotron LLM client.

Responsibilities:
- Load NVIDIA configuration from .env
- Connect to NVIDIA hosted endpoint
- Support normal text generation
- Support structured JSON generation
- Parse JSON-mode responses into Python dictionaries
"""

from __future__ import annotations

import os
import re
import json
from pathlib import Path
from typing import Any, Dict, Union

from dotenv import load_dotenv
from openai import OpenAI


# ---------------------------------------------------------------------
# PROJECT CONFIGURATION
# ---------------------------------------------------------------------

# Automatically resolve the project root.
# File location:
#   project_root/ai_engine/llm_client.py
#
# parents[0] = ai_engine
# parents[1] = project_root

PROJECT_ROOT = Path(__file__).resolve().parents[1]

ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(ENV_FILE)


# ---------------------------------------------------------------------
# ENVIRONMENT VARIABLES
# ---------------------------------------------------------------------

NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")

NVIDIA_MODEL_NAME = os.getenv(
    "NVIDIA_MODEL_NAME",
    "nvidia/nemotron-3.5-lightning-30b-a3b"
)

NVIDIA_BASE_URL = os.getenv(
    "NVIDIA_BASE_URL",
    "https://integrate.api.nvidia.com/v1"
)


# ---------------------------------------------------------------------
# VALIDATION
# ---------------------------------------------------------------------

if not NVIDIA_API_KEY:
    raise RuntimeError(
        "NVIDIA_API_KEY is not configured in the project .env file."
    )


# ---------------------------------------------------------------------
# OPENAI-COMPATIBLE NVIDIA CLIENT
# ---------------------------------------------------------------------

client = OpenAI(
    base_url=NVIDIA_BASE_URL,
    api_key=NVIDIA_API_KEY,
    timeout=300.0,
)


# ---------------------------------------------------------------------
# JSON PARSER
# ---------------------------------------------------------------------

def _parse_json_response(
    text: str
) -> Dict[str, Any]:
    """
    Convert a model JSON response string into a Python dictionary.

    Handles:
    1. Pure JSON
    2. JSON inside markdown code fences
    3. Extra whitespace
    """

    if not isinstance(text, str):
        raise TypeError(
            "JSON response must be a string before parsing."
        )

    text = text.strip()

    if not text:
        raise ValueError(
            "Nemotron returned an empty response."
        )

    # -------------------------------------------------------------
    # Remove markdown JSON code fences if present.
    # -------------------------------------------------------------

    if text.startswith("```"):
        lines = text.splitlines()

        if lines:
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        text = "\n".join(lines).strip()

    # -------------------------------------------------------------
    # Parse JSON.
    # -------------------------------------------------------------

    try:
        parsed = json.loads(text)

    except json.JSONDecodeError as exc:

        # ---------------------------------------------------------
        # Try to recover a JSON object if the model added text
        # before or after the JSON.
        # ---------------------------------------------------------

        start = text.find("{")
        end = text.rfind("}")

        if start == -1 or end == -1 or end <= start:
            raise ValueError(
                "Nemotron response did not contain valid JSON."
            ) from exc

        candidate = text[start:end + 1]

        try:
            parsed = json.loads(candidate)

        except json.JSONDecodeError as inner_exc:
            raise ValueError(
                "Nemotron response contained invalid JSON."
            ) from inner_exc

    # -------------------------------------------------------------
    # Structured agent responses must be JSON objects.
    # -------------------------------------------------------------

    if not isinstance(parsed, dict):
        raise ValueError(
            "Expected JSON object but received "
            f"{type(parsed).__name__}."
        )

    return parsed


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
    Generate a response from NVIDIA Nemotron.

    Parameters
    ----------
    prompt:
        User prompt sent to Nemotron.

    json_mode:
        If True:
        - Requests JSON output.
        - Disables model thinking.
        - Parses the response into a Python dictionary.

    max_tokens:
        Maximum generated tokens.

    temperature:
        Sampling temperature.

    Returns
    -------
    str
        Normal text response.

    dict
        Parsed JSON object when json_mode=True.
    """

    if not isinstance(prompt, str):
        raise TypeError(
            "prompt must be a string."
        )

    if not prompt.strip():
        raise ValueError(
            "prompt cannot be empty."
        )

    # -------------------------------------------------------------
    # Request configuration
    # -------------------------------------------------------------

    request_kwargs = {
        "model": NVIDIA_MODEL_NAME,

        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],

        "temperature": temperature,

        "max_tokens": max_tokens,

        "stream": False,

        # Structured JSON output should not spend the token
        # budget on reasoning traces.
        "extra_body": {
            "chat_template_kwargs": {
                "enable_thinking": False
            }
        },
    }

    # -------------------------------------------------------------
    # JSON mode
    # -------------------------------------------------------------

    if json_mode:
        request_kwargs["response_format"] = {
            "type": "json_object"
        }

    # -------------------------------------------------------------
    # API call
    # -------------------------------------------------------------

    completion = client.chat.completions.create(
        **request_kwargs
    )

    # -------------------------------------------------------------
    # Extract response text
    # -------------------------------------------------------------

    if not completion.choices:
        raise RuntimeError(
            "Nemotron returned no choices."
        )

    message = completion.choices[0].message

    content = message.content

    if content is None:
        raise RuntimeError(
            "Nemotron returned an empty message content."
        )

    # -------------------------------------------------------------
    # JSON MODE
    # -------------------------------------------------------------

    if json_mode:
        return _parse_json_response(content)

    # -------------------------------------------------------------
    # NORMAL TEXT MODE
    # -------------------------------------------------------------

    return content


# ---------------------------------------------------------------------
# CONNECTION TEST
# ---------------------------------------------------------------------

def test_connection() -> Dict[str, Any]:
    """
    Test the NVIDIA Nemotron endpoint.
    """

    response = generate_response(
        "Respond with exactly one short sentence confirming "
        "that the email forensics AI engine is online.",
        json_mode=False,
        max_tokens=100,
        temperature=0.0,
    )

    return {
        "status": "CONNECTED",
        "model": NVIDIA_MODEL_NAME,
        "response": response,
    }


# ---------------------------------------------------------------------
# ROBUST JSON OBJECT EXTRACTION
# ---------------------------------------------------------------------

def _extract_json_object(text):
    """
    Extract a JSON object from an LLM response.

    Supports:
    1. Plain JSON
    2. Markdown JSON fences
    3. JSON surrounded by explanatory text
    4. Balanced JSON object extraction

    Returns:
        dict

    Raises:
        ValueError
    """

    if isinstance(text, dict):
        return text

    if text is None:
        raise ValueError(
            "LLM response was empty."
        )

    text = str(text).strip()

    if not text:
        raise ValueError(
            "LLM response was empty."
        )

    # --------------------------------------------------------
    # Direct JSON
    # --------------------------------------------------------

    try:

        parsed = json.loads(text)

        if isinstance(parsed, dict):
            return parsed

    except (
        json.JSONDecodeError,
        TypeError
    ):
        pass

    # --------------------------------------------------------
    # Remove markdown fences
    # --------------------------------------------------------

    cleaned = re.sub(
        r"```(?:json)?",
        "",
        text,
        flags=re.IGNORECASE
    )

    cleaned = cleaned.replace(
        "```",
        ""
    ).strip()

    try:

        parsed = json.loads(cleaned)

        if isinstance(parsed, dict):
            return parsed

    except (
        json.JSONDecodeError,
        TypeError
    ):
        pass

    # --------------------------------------------------------
    # Balanced-object extraction
    # --------------------------------------------------------

    start = cleaned.find("{")

    if start == -1:
        raise ValueError(
            "Nemotron response did not contain "
            "a JSON object."
        )

    depth = 0
    in_string = False
    escaped = False

    for index in range(
        start,
        len(cleaned)
    ):

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

                candidate = cleaned[
                    start:index + 1
                ]

                try:

                    parsed = json.loads(
                        candidate
                    )

                    if isinstance(parsed, dict):
                        return parsed

                except (
                    json.JSONDecodeError,
                    TypeError
                ):

                    raise ValueError(
                        "Nemotron response contained "
                        "an invalid JSON object."
                    )

    raise ValueError(
        "Nemotron response did not contain "
        "valid JSON."
    )


# ---------------------------------------------------------------------
# PUBLIC API
# ---------------------------------------------------------------------

__all__ = [
    "generate_response",
    "test_connection",
    "NVIDIA_MODEL_NAME",
    "NVIDIA_BASE_URL",
]