from __future__ import annotations



import json

from pathlib import Path

from typing import Any



from fastapi import APIRouter, HTTPException, Query



from database.cases_repository import get_case

from ai_engine.multi_agent_debate.debater_nodes import run_debate

from ai_engine.rag.retrieval_engine import semantic_search
from ai_engine.ml_phishing_detector import predict_email





# ============================================================

# ROUTER

# ============================================================



router = APIRouter(

    tags=["investigation"]

)





# ============================================================

# PROJECT PATHS

# ============================================================



PROJECT_ROOT = (

    Path(__file__)

    .resolve()

    .parents[1]

)



PARSED_EMAILS_DIR = (

    PROJECT_ROOT

    / "evidence"

    / "parsed_emails"

).resolve()





# ============================================================

# EVIDENCE LOADER

# ============================================================



def _load_case_evidence(

    case_id: str,

    case: dict[str, Any],

) -> tuple[Path, dict[str, Any]]:

    """

    Load the forensic JSON corresponding to a database case.



    The source filename comes from the database case record.

    The resolved evidence file must remain inside the

    permitted parsed-emails directory.

    """



    filename = str(

        case.get("filename") or ""

    ).strip()



    if not filename:

        raise HTTPException(

            status_code=422,

            detail=(

                "Case does not contain a source filename."

            ),

        )



    # Prevent directory traversal through the database value.

    source_name = Path(filename).name



    stem = Path(source_name).stem



    if not stem:

        raise HTTPException(

            status_code=422,

            detail=(

                "Case filename does not contain "

                "a valid stem."

            ),

        )



    evidence_path = (

        PARSED_EMAILS_DIR

        / f"{stem}_forensic.json"

    ).resolve()



    # Security boundary.

    if (

        PARSED_EMAILS_DIR

        not in evidence_path.parents

    ):

        raise HTTPException(

            status_code=400,

            detail=(

                "Resolved evidence path is outside "

                "the permitted evidence directory."

            ),

        )



    if not evidence_path.is_file():

        raise HTTPException(

            status_code=404,

            detail=(

                "Parsed forensic evidence not found "

                f"for case {case_id}: "

                f"{evidence_path.name}"

            ),

        )



    try:

        with evidence_path.open(

            "r",

            encoding="utf-8",

        ) as handle:

            evidence = json.load(handle)



    except json.JSONDecodeError as exc:

        raise HTTPException(

            status_code=500,

            detail=(

                "Parsed forensic evidence contains "

                "invalid JSON."

            ),

        ) from exc



    except OSError as exc:

        raise HTTPException(

            status_code=500,

            detail=(

                "Unable to read parsed forensic "

                "evidence."

            ),

        ) from exc



    if not isinstance(

        evidence,

        dict,

    ):

        raise HTTPException(

            status_code=500,

            detail=(

                "Parsed forensic evidence must be "

                "a JSON object."

            ),

        )



    return evidence_path, evidence





# ============================================================

# RAG QUERY BUILDER

# ============================================================



def _build_rag_query(

    case: dict[str, Any],

    evidence: dict[str, Any],

) -> str:

    """

    Build a compact investigation query for RAG retrieval.



    Only forensic metadata is used to construct the query.

    The purpose is to retrieve related investigation memory,

    not to expose the complete original email body.

    """



    parts: list[str] = []



    subject = str(

        case.get("subject") or ""

    ).strip()



    sender = str(

        case.get("sender_clean")

        or case.get("sender_raw")

        or ""

    ).strip()



    recipient = str(

        case.get("recipient_raw") or ""

    ).strip()



    if subject:

        parts.append(

            f"subject {subject}"

        )



    if sender:

        parts.append(

            f"sender {sender}"

        )



    if recipient:

        parts.append(

            f"recipient {recipient}"

        )



    # --------------------------------------------------------

    # Extract useful forensic indicators.

    # --------------------------------------------------------



    forensic_flags = evidence.get(

        "forensic_flags",

        [],

    )



    if isinstance(

        forensic_flags,

        list,

    ):

        for flag in forensic_flags[:10]:

            if isinstance(

                flag,

                str,

            ):

                parts.append(

                    f"forensic flag {flag}"

                )



    urls = evidence.get(

        "urls",

        [],

    )



    if isinstance(

        urls,

        list,

    ):

        if urls:

            parts.append(

                f"urls {len(urls)}"

            )



    attachments = evidence.get(

        "attachments",

        [],

    )



    if isinstance(

        attachments,

        list,

    ):

        if attachments:

            parts.append(

                f"attachments {len(attachments)}"

            )



    # --------------------------------------------------------

    # Fallback query.

    # --------------------------------------------------------



    if not parts:

        parts.append(

            "email forensic investigation"

        )



    query = " ".join(parts)



    # Keep retrieval query bounded.

    return query[:1000]





# ============================================================

# PRIVACY-SAFE RAG RETRIEVAL

# ============================================================



def _retrieve_rag_context(

    case: dict[str, Any],

    evidence: dict[str, Any],

    *,

    top_k: int = 5,

) -> dict[str, Any]:

    """

    Perform read-only semantic retrieval.



    IMPORTANT:

    Raw retrieved text is deliberately excluded from

    the returned investigation context.



    Only provenance, similarity, email ID, chunk ID,

    and privacy metadata are retained.

    """



    query = _build_rag_query(

        case,

        evidence,

    )



    try:

        results = semantic_search(

            query=query,

            top_k=top_k,

        )



    except Exception as exc:

        raise RuntimeError(

            "RAG semantic retrieval failed."

        ) from exc



    safe_results: list[dict[str, Any]] = []



    for result in results:



        if not isinstance(

            result,

            dict,

        ):

            continue



        # ----------------------------------------------------

        # Extract privacy information when available.

        # ----------------------------------------------------



        private_vector = result.get(

            "private_vector"

        )



        privacy_safe = result.get(

            "privacy_safe",

            True,

        )



        raw_text_released = result.get(

            "raw_text_released",

            False,

        )



        vector_length = result.get(

            "vector_length"

        )



        # ----------------------------------------------------

        # Never include retrieved raw text.

        # ----------------------------------------------------



        safe_result = {

            "rank": result.get(

                "rank"

            ),



            "similarity": result.get(

                "similarity"

            ),



            "email_id": result.get(

                "email_id"

            ),



            "chunk_id": result.get(

                "chunk_id"

            ),



            "chunk_index": result.get(

                "chunk_index"

            ),



            "source_file": result.get(

                "source_file"

            ),



            "privacy_safe": bool(

                privacy_safe

            ),



            "raw_text_released": bool(

                raw_text_released

            ),



            "vector_length": vector_length,

        }



        # ----------------------------------------------------

        # Include vector only when explicitly supplied by

        # the privacy layer.

        # ----------------------------------------------------



        if isinstance(

            private_vector,

            list,

        ):

            safe_result[

                "private_vector"

            ] = private_vector



        safe_results.append(

            safe_result

        )



    return {

        "enabled": True,



        "retrieval_method": (

            "semantic_cosine_similarity"

        ),



        "query": query,



        "requested_top_k": top_k,



        "result_count": len(

            safe_results

        ),



        "raw_text_released": False,



        "results": safe_results,

    }





# ============================================================

# RAG SECURITY VALIDATION

# ============================================================



def _validate_rag_context(

    rag_context: dict[str, Any],

) -> None:

    """

    Validate the privacy guarantees before RAG context

    is attached to the investigation.



    This is intentionally strict.

    """



    if rag_context.get(

        "raw_text_released"

    ) is not False:

        raise ValueError(

            "RAG security violation: "

            "raw retrieved text must not be released."

        )



    results = rag_context.get(

        "results",

        [],

    )



    if not isinstance(

        results,

        list,

    ):

        raise ValueError(

            "RAG results must be a list."

        )



    for result in results:



        if not isinstance(

            result,

            dict,

        ):

            raise ValueError(

                "Invalid RAG result."

            )



        if result.get(

            "raw_text_released"

        ) is True:

            raise ValueError(

                "RAG security violation: "

                "individual result released raw text."

            )





# ============================================================

# INVESTIGATION ENDPOINT

# ============================================================



@router.post(

    "/cases/{case_id}/investigate"

)

def investigate_case(

    case_id: str,

    rounds: int = Query(

        default=1,

        ge=1,

        le=2,

        description=(

            "Number of supported debate rounds."

        ),

    ),

) -> dict[str, Any]:

    """

    Run a complete AI forensic investigation.



    Flow:



        Database case

            ↓

        Parsed forensic evidence

            ↓

        RAG retrieval

            ↓

        Privacy-safe retrieval context

            ↓

        Multi-agent debate

            ↓

        Final triage

    """



    # ========================================================

    # STEP 1 — LOAD CASE

    # ========================================================



    case = get_case(

        case_id

    )



    if case is None:

        raise HTTPException(

            status_code=404,

            detail=(

                f"Case not found: {case_id}"

            ),

        )



    # ========================================================

    # STEP 2 — LOAD FORENSIC EVIDENCE

    # ========================================================



    evidence_path, evidence = (

        _load_case_evidence(

            case_id,

            case,

        )

    )



    # ========================================================

    # STEP 2A — ML PHISHING DETECTION
    # ========================================================

    # Use the parsed email's subject and body without changing original evidence.
    email_data = evidence.get("email", {})
    if not isinstance(email_data, dict):
        email_data = {}

    email_subject = str(
        email_data.get("subject") or case.get("subject") or ""
    ).strip()
    email_body = str(email_data.get("body") or "").strip()
    ml_text = "\n".join(
        part for part in (email_subject, email_body) if part
    )

    if ml_text:
        try:
            ml_prediction = predict_email(ml_text)
        except Exception as exc:
            # Keep the rest of the forensic investigation available if ML fails.
            print("ML PHISHING DETECTOR ERROR:", type(exc).__name__, str(exc))
            ml_prediction = {
                "status": "unavailable",
                "error_type": type(exc).__name__,
                "model": "LinearSVC",
            }
    else:
        ml_prediction = {
            "status": "unavailable",
            "reason": "No subject or body text was found in parsed evidence.",
            "model": "LinearSVC",
        }

    # ========================================================
    # STEP 3 — RAG RETRIEVAL
    # ========================================================



    try:

        rag_context = (

            _retrieve_rag_context(

                case,

                evidence,

                top_k=5,

            )

        )



        _validate_rag_context(

            rag_context

        )



    except ValueError as exc:

        raise HTTPException(

            status_code=422,

            detail=str(exc),

        ) from exc



    except Exception as exc:

        print(

            "RAG INVESTIGATION ERROR:",

            type(exc).__name__,

            str(exc),

        )



        raise HTTPException(

            status_code=500,

            detail=(

                "RAG retrieval failed during "

                "investigation."

            ),

        ) from exc



    # ========================================================

    # STEP 4 — CREATE INVESTIGATION CONTEXT

    # ========================================================



    # Do not modify the original evidence object.

    #

    # A shallow copy is sufficient because we only add a

    # top-level field containing a new RAG structure.



    investigation_evidence = dict(

        evidence

    )



    investigation_evidence[

        "rag_context"

    ] = rag_context




    investigation_evidence["ml_prediction"] = ml_prediction
    # ========================================================

    # STEP 5 — MULTI-AGENT DEBATE

    # ========================================================



    try:



        print(

            "STARTING MULTI-AGENT DEBATE"

        )



        print(

            "CASE ID:",

            case_id

        )



        print(

            "DEBATE ROUNDS:",

            rounds

        )



        debate_result = run_debate(

            investigation_evidence,

            rounds=rounds,

        )



        print(

            "MULTI-AGENT DEBATE COMPLETED"

        )



    except ValueError as exc:



        print(

            "DEBATE VALUE ERROR:",

            type(exc).__name__,

            str(exc),

        )



        raise HTTPException(

            status_code=422,

            detail=(

                "Multi-agent debate validation failed: "

                f"{str(exc)}"

            ),

        ) from exc



    except Exception as exc:



        # TEMPORARY DEBUGGING

        #

        # This exposes the actual internal exception so

        # we can identify the problem during development.

        # Remove the exception detail before production.



        print(

            "MULTI-AGENT DEBATE ERROR:"

        )



        print(

            "ERROR TYPE:",

            type(exc).__name__

        )



        print(

            "ERROR MESSAGE:",

            str(exc)

        )



        raise HTTPException(

            status_code=500,

            detail=(

                "Investigation engine failed "

                "to complete the case. "

                f"Error: {type(exc).__name__}: {str(exc)}"

            ),

        ) from exc



    # ========================================================

    # STEP 6 — BUILD API RESPONSE

    # ========================================================



    return {



        "status": "completed",



        "case": {



            "case_id": case.get(

                "case_id"

            ),



            "filename": case.get(

                "filename"

            ),



            "md5_hash": case.get(

                "md5_hash"

            ),



            "evidence_file": str(

                evidence_path.relative_to(

                    PROJECT_ROOT

                )

            ),

        },



        "retrieval": {



            "enabled": True,



            "method": (

                rag_context[

                    "retrieval_method"

                ]

            ),



            "query": (

                rag_context[

                    "query"

                ]

            ),



            "result_count": (

                rag_context[

                    "result_count"

                ]

            ),



            "raw_text_released": (

                rag_context[

                    "raw_text_released"

                ]

            ),



            "results": (

                rag_context[

                    "results"

                ]

            ),

        },



        "ml_prediction": ml_prediction,

        "investigation": debate_result,

    }
