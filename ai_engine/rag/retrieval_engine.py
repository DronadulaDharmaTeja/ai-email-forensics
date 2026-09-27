"""
Secure Email Forensics
RAG Retrieval Engine

Privacy-aware retrieval over existing
RAG chunk, embedding, and investigation-memory artifacts.

Architecture:

Query
  ↓
Semantic Retrieval
  ↓
RAG Chunk Ranking
  ↓
Investigation Memory Lookup
  ↓
Scope Matrix
  ↓
Privacy Mask
  ↓
Privacy-Safe Memory Context

The original forensic evidence and source artifacts
are never modified.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


import numpy as np
from sentence_transformers import SentenceTransformer


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = (
    Path(__file__).resolve().parents[2]
)


RAG_DIR = (
    PROJECT_ROOT
    / "ai_engine"
    / "rag"
)


MEMORY_DIR = (
    PROJECT_ROOT
    / "ai_engine"
    / "investigation_memory"
)


PRIVACY_DIR = (
    PROJECT_ROOT
    / "database"
    / "privacy_vector_store"
)


CHUNKS_FILE = (
    RAG_DIR
    / "chunks"
    / "rag_chunks.json"
)


EMBEDDINGS_FILE = (
    RAG_DIR
    / "embeddings"
    / "rag_embeddings.npy"
)


MEMORY_FILE = (
    MEMORY_DIR
    / "investigation_memory_master.json"
)


EMBEDDING_MODEL_NAME = (
    "sentence-transformers/all-MiniLM-L6-v2"
)


# ============================================================
# PRIVACY IMPORTS
# ============================================================

from database.privacy_vector_store.privacy_pipeline import (
    build_privacy_vector,
)


# ============================================================
# SAFE FILE LOADER
# ============================================================

def _load_json(
    path: Path,
) -> Any:
    """
    Load JSON from a project-local file.
    """

    resolved = path.resolve()

    if PROJECT_ROOT.resolve() not in resolved.parents:
        raise ValueError(
            f"Refusing to read file outside project root: "
            f"{resolved}"
        )

    if not resolved.is_file():
        raise FileNotFoundError(
            f"Required file not found: {resolved}"
        )

    with resolved.open(
        "r",
        encoding="utf-8",
    ) as handle:

        return json.load(handle)


# ============================================================
# LOAD RAG CHUNKS
# ============================================================

chunks = _load_json(
    CHUNKS_FILE
)


if not isinstance(
    chunks,
    list,
):

    raise ValueError(
        "RAG chunks must be a JSON list."
    )


# ============================================================
# LOAD EMBEDDINGS
# ============================================================

if not EMBEDDINGS_FILE.is_file():

    raise FileNotFoundError(
        f"RAG embeddings not found: "
        f"{EMBEDDINGS_FILE}"
    )


embeddings = np.load(
    EMBEDDINGS_FILE,
    allow_pickle=False,
)


if embeddings.ndim != 2:

    raise ValueError(
        "RAG embeddings must be a 2D array."
    )


if len(chunks) != len(embeddings):

    raise ValueError(
        "RAG chunk count does not match "
        "embedding count."
    )


# ============================================================
# LOAD INVESTIGATION MEMORY
# ============================================================

memory_data = _load_json(
    MEMORY_FILE
)


if not isinstance(
    memory_data,
    dict,
):

    raise ValueError(
        "Investigation memory must be a JSON object."
    )


# ============================================================
# FIND MEMORY RECORDS
# ============================================================

memory_records = None


for candidate in [
    "records",
    "memories",
    "claims",
    "items",
    "data",
]:

    value = memory_data.get(
        candidate
    )

    if isinstance(
        value,
        list,
    ):

        memory_records = value
        break


if memory_records is None:

    raise ValueError(
        "Investigation memory records not found."
    )


# ============================================================
# BUILD MEMORY INDEX
# ============================================================

memory_index: dict[
    str,
    dict[str, Any],
] = {}


for record in memory_records:

    if not isinstance(
        record,
        dict,
    ):
        continue

    email_id = record.get(
        "email_id"
    )

    if email_id:

        memory_index[
            str(email_id)
        ] = record


# ============================================================
# NORMALIZE RAG EMBEDDINGS
# ============================================================

embedding_norms = np.linalg.norm(
    embeddings,
    axis=1,
    keepdims=True,
)


if np.any(
    embedding_norms == 0
):

    raise ValueError(
        "Zero-norm embedding detected."
    )


normalized_embeddings = (
    embeddings
    / embedding_norms
)


# ============================================================
# EMBEDDING MODEL
# ============================================================

embedding_model = SentenceTransformer(
    EMBEDDING_MODEL_NAME
)


# ============================================================
# PRIVACY-SAFE MEMORY
# ============================================================

def build_privacy_safe_memory(
    email_id: str,
    *,
    epsilon: float = 1.0,
    seed: int | None = 42,
) -> dict[str, Any] | None:
    """
    Convert one investigation-memory record into
    a privacy-safe representation.

    The original memory record is never modified.

    Returns:

        {
            "email_id": "...",
            "private_vector": [...],
            "vector_length": 4,
            "privacy": {...},
            "scope": {...},
            "source_policy": {...}
        }

    No raw investigation-memory text is returned.
    """

    record = memory_index.get(
        str(email_id)
    )

    if record is None:
        return None

    result = build_privacy_vector(
        record,
        epsilon=epsilon,
        seed=seed,
    )

    return {
        "email_id": str(email_id),

        "private_vector": result[
            "private_vector"
        ],

        "vector_length": result[
            "vector_length"
        ],

        "privacy": result[
            "privacy"
        ],

        "scope": result[
            "scope"
        ],

        "source_policy": result[
            "source_policy"
        ],
    }


# ============================================================
# SEMANTIC SEARCH
# ============================================================

def semantic_search(
    query: str,
    top_k: int = 5,
    *,
    privacy_safe: bool = False,
    epsilon: float = 1.0,
    seed: int | None = 42,
):
    """
    Semantic search over existing RAG embeddings.

    privacy_safe=False:
        Preserves the original retrieval behavior.

    privacy_safe=True:
        Raw investigation-memory records are replaced
        with privacy-safe vectors.

    The underlying RAG artifacts are read-only.
    """

    if not isinstance(
        query,
        str,
    ):

        raise TypeError(
            "query must be a string."
        )


    query = query.strip()


    if not query:

        raise ValueError(
            "query cannot be empty."
        )


    if not isinstance(
        top_k,
        int,
    ) or top_k <= 0:

        raise ValueError(
            "top_k must be a positive integer."
        )


    if not isinstance(
        privacy_safe,
        bool,
    ):

        raise TypeError(
            "privacy_safe must be True or False."
        )


    # --------------------------------------------------------
    # QUERY EMBEDDING
    # --------------------------------------------------------

    query_embedding = embedding_model.encode(
        [query],
        convert_to_numpy=True,
        normalize_embeddings=True,
        show_progress_bar=False,
    )[0]


    # --------------------------------------------------------
    # COSINE SIMILARITY
    # --------------------------------------------------------

    similarities = (
        normalized_embeddings
        @ query_embedding
    )


    actual_k = min(
        top_k,
        len(chunks),
    )


    top_indices = np.argsort(
        similarities
    )[::-1][:actual_k]


    # --------------------------------------------------------
    # BUILD RESULTS
    # --------------------------------------------------------

    results = []


    for rank, index in enumerate(
        top_indices,
        start=1,
    ):

        chunk = chunks[
            int(index)
        ]


        email_id = str(
            chunk.get(
                "email_id",
                "",
            )
        )


        # ----------------------------------------------------
        # MEMORY
        # ----------------------------------------------------

        if privacy_safe:

            memory = build_privacy_safe_memory(
                email_id,
                epsilon=epsilon,
                seed=seed,
            )

        else:

            memory = memory_index.get(
                email_id
            )


        # ----------------------------------------------------
        # RESULT
        # ----------------------------------------------------

        results.append({

            "rank": rank,

            "similarity": float(
                similarities[index]
            ),

            "chunk_id": chunk.get(
                "chunk_id"
            ),

            "email_id": email_id,

            "chunk_index": chunk.get(
                "chunk_index"
            ),

            "source_file": chunk.get(
                "source_file"
            ),

            "text": chunk.get(
                "text"
            ),

            "character_count": chunk.get(
                "character_count"
            ),

            "memory": memory,

            "privacy_safe": privacy_safe,

        })


    return results


# ============================================================
# CONVENIENCE SEARCH
# ============================================================

def search(
    query: str,
    top_k: int = 5,
    *,
    privacy_safe: bool = False,
):
    """
    Convenience alias for semantic_search.
    """

    return semantic_search(
        query=query,
        top_k=top_k,
        privacy_safe=privacy_safe,
    )


# ============================================================
# LEXICAL MEMORY SEARCH
# ============================================================

def search_memory(
    query: str,
    limit: int = 10,
):
    """
    Deterministic lexical search across
    investigation-memory records.

    This function preserves the original
    behavior for compatibility.
    """

    if not isinstance(
        query,
        str,
    ):

        raise TypeError(
            "query must be a string."
        )


    query = query.strip().lower()


    if not query:

        raise ValueError(
            "query cannot be empty."
        )


    if not isinstance(
        limit,
        int,
    ) or limit <= 0:

        raise ValueError(
            "limit must be a positive integer."
        )


    query_terms = [
        term
        for term in query.split()
        if len(term) > 2
    ]


    scored = []


    for record in memory_records:

        if not isinstance(
            record,
            dict,
        ):
            continue


        searchable_text = json.dumps(
            record,
            ensure_ascii=False,
        ).lower()


        score = sum(
            searchable_text.count(term)
            for term in query_terms
        )


        if score > 0:

            scored.append(
                (
                    score,
                    record,
                )
            )


    scored.sort(
        key=lambda item: item[0],
        reverse=True,
    )


    results = []


    for rank, (
        score,
        record,
    ) in enumerate(
        scored[:limit],
        start=1,
    ):

        results.append({

            "rank": rank,

            "score": score,

            "email_id": record.get(
                "email_id"
            ),

            "record": record,

        })


    return results


# ============================================================
# PRIVACY-SAFE LEXICAL MEMORY SEARCH
# ============================================================

def search_memory_private(
    query: str,
    limit: int = 10,
    *,
    epsilon: float = 1.0,
    seed: int | None = 42,
):
    """
    Privacy-safe lexical investigation-memory search.

    Search ranking is performed internally over the
    investigation-memory records.

    Returned records contain only:

        email_id
        private_vector
        scope
        privacy audit
        source policy

    Raw memory text is not returned.
    """

    raw_results = search_memory(
        query=query,
        limit=limit,
    )


    results = []


    for result in raw_results:

        email_id = result.get(
            "email_id"
        )


        private_memory = (
            build_privacy_safe_memory(
                email_id,
                epsilon=epsilon,
                seed=seed,
            )
        )


        if private_memory is None:
            continue


        results.append({

            "rank": result[
                "rank"
            ],

            "score": result[
                "score"
            ],

            "email_id": email_id,

            "memory": private_memory,

        })


    return results


# ============================================================
# BUILD EVIDENCE CONTEXT
# ============================================================

def build_evidence_context(
    query: str,
    top_k: int = 5,
    *,
    privacy_safe: bool = False,
    epsilon: float = 1.0,
    seed: int | None = 42,
):
    """
    Build provenance-preserving evidence context.

    privacy_safe=True enables privacy-protected
    investigation-memory output.
    """

    results = semantic_search(
        query=query,
        top_k=top_k,
        privacy_safe=privacy_safe,
        epsilon=epsilon,
        seed=seed,
    )


    contexts = []


    for result in results:

        contexts.append({

            "rank": result[
                "rank"
            ],

            "similarity": result[
                "similarity"
            ],

            "email_id": result[
                "email_id"
            ],

            "chunk_id": result[
                "chunk_id"
            ],

            "source_file": result[
                "source_file"
            ],

            "text": result[
                "text"
            ],

            "memory": result[
                "memory"
            ],

            "privacy_safe": result[
                "privacy_safe"
            ],

            "provenance": {

                "email_id": result[
                    "email_id"
                ],

                "chunk_id": result[
                    "chunk_id"
                ],

                "source_file": result[
                    "source_file"
                ],

            },

        })


    return {

        "query": query,

        "retrieval_method": (
            "semantic_cosine_similarity"
        ),

        "top_k": top_k,

        "privacy_safe": privacy_safe,

        "results": contexts,

    }


# ============================================================
# PRIVACY-SAFE EVIDENCE CONTEXT
# ============================================================

def build_privacy_safe_context(
    query: str,
    top_k: int = 5,
    *,
    epsilon: float = 1.0,
    seed: int | None = 42,
):
    """
    Build a privacy-safe RAG evidence context.

    This is the preferred entry point when investigation
    memory must not be returned as raw text.
    """

    return build_evidence_context(
        query=query,
        top_k=top_k,
        privacy_safe=True,
        epsilon=epsilon,
        seed=seed,
    )


# ============================================================
# STATISTICS
# ============================================================

def statistics():

    return {

        "project_root": str(
            PROJECT_ROOT
        ),

        "embedding_model": (
            EMBEDDING_MODEL_NAME
        ),

        "chunk_count": len(
            chunks
        ),

        "embedding_shape": list(
            embeddings.shape
        ),

        "embedding_dtype": str(
            embeddings.dtype
        ),

        "memory_record_count": len(
            memory_records
        ),

        "memory_index_count": len(
            memory_index
        ),

        "retrieval_method": (
            "cosine_similarity"
        ),

        "privacy_pipeline": (
            "database.privacy_vector_store"
        ),

        "privacy_safe_retrieval": True,

    }


# ============================================================
# PRIVACY INTEGRATION TEST
# ============================================================

def test_privacy_integration(
    query: str = "phishing suspicious email",
):
    """
    Verify that semantic RAG retrieval can produce
    a privacy-safe investigation context.
    """

    print("=" * 70)
    print("RAG PRIVACY INTEGRATION TEST")
    print("=" * 70)


    print("\nProject root:")
    print(
        PROJECT_ROOT
    )


    print("\nQuery:")
    print(
        query
    )


    result = build_privacy_safe_context(
        query=query,
        top_k=3,
        epsilon=1.0,
        seed=42,
    )


    print("\nRetrieval method:")
    print(
        result[
            "retrieval_method"
        ]
    )


    print("\nPrivacy safe:")
    print(
        result[
            "privacy_safe"
        ]
    )


    print("\nResult count:")
    print(
        len(
            result[
                "results"
            ]
        )
    )


    for item in result[
        "results"
    ]:

        print(
            "\n----------------------------------------"
        )

        print(
            "Rank:",
            item["rank"],
        )

        print(
            "Email:",
            item["email_id"],
        )

        print(
            "Similarity:",
            round(
                item["similarity"],
                6,
            ),
        )

        print(
            "Privacy safe:",
            item["privacy_safe"],
        )


        memory = item.get(
            "memory"
        )


        if memory:

            print(
                "Private vector:",
                memory[
                    "private_vector"
                ],
            )

            print(
                "Vector length:",
                memory[
                    "vector_length"
                ],
            )

            print(
                "Raw text released:",
                memory[
                    "source_policy"
                ][
                    "raw_text_released"
                ],
            )


            assert (
                memory[
                    "source_policy"
                ][
                    "raw_text_released"
                ]
                is False
            )


            assert (
                memory[
                    "source_policy"
                ][
                    "original_record_modified"
                ]
                is False
            )


            assert (
                memory[
                    "source_policy"
                ][
                    "out_of_scope_fields_in_vector"
                ]
                is False
            )


    print(
        "\nRAG PRIVACY INTEGRATION TEST: PASS"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    test_privacy_integration()