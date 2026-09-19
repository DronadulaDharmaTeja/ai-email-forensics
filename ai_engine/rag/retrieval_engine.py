"""
Secure Email Forensics
RAG Retrieval Engine

Read-only semantic retrieval over the existing
RAG chunk and embedding artifacts.
"""

from pathlib import Path
import json

import numpy as np
from sentence_transformers import SentenceTransformer


PROJECT_ROOT = Path(
    "/content/drive/MyDrive/email forensics  with advance features"
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


with open(
    CHUNKS_FILE,
    "r",
    encoding="utf-8"
) as f:

    chunks = json.load(f)


embeddings = np.load(
    EMBEDDINGS_FILE,
    allow_pickle=False
)


with open(
    MEMORY_FILE,
    "r",
    encoding="utf-8"
) as f:

    memory_data = json.load(f)


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
        list
    ):

        memory_records = value
        break


if memory_records is None:

    raise ValueError(
        "Investigation memory records not found."
    )


memory_index = {}

for record in memory_records:

    if not isinstance(
        record,
        dict
    ):
        continue

    email_id = record.get(
        "email_id"
    )

    if email_id:

        memory_index[
            str(email_id)
        ] = record


embedding_norms = np.linalg.norm(
    embeddings,
    axis=1,
    keepdims=True
)


if np.any(
    embedding_norms == 0
):

    raise ValueError(
        "Zero-norm embedding detected."
    )


normalized_embeddings = (
    embeddings / embedding_norms
)


embedding_model = SentenceTransformer(
    EMBEDDING_MODEL_NAME
)


def semantic_search(
    query: str,
    top_k: int = 5
):
    """
    Semantic search over existing RAG embeddings.

    Returns ranked chunks with provenance and
    corresponding investigation-memory records.
    """

    if not isinstance(
        query,
        str
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
        int
    ) or top_k <= 0:

        raise ValueError(
            "top_k must be a positive integer."
        )

    query_embedding = embedding_model.encode(
        [query],
        convert_to_numpy=True,
        normalize_embeddings=True,
        show_progress_bar=False
    )[0]

    similarities = (
        normalized_embeddings
        @ query_embedding
    )

    actual_k = min(
        top_k,
        len(chunks)
    )

    top_indices = np.argsort(
        similarities
    )[::-1][:actual_k]

    results = []

    for rank, index in enumerate(
        top_indices,
        start=1
    ):

        chunk = chunks[
            int(index)
        ]

        email_id = str(
            chunk.get(
                "email_id",
                ""
            )
        )

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

            "memory": memory_index.get(
                email_id
            ),

        })

    return results


def search(
    query: str,
    top_k: int = 5
):
    """
    Convenience alias for semantic_search.
    """

    return semantic_search(
        query=query,
        top_k=top_k
    )


def search_memory(
    query: str,
    limit: int = 10
):
    """
    Deterministic lexical search across
    investigation-memory records.
    """

    if not isinstance(
        query,
        str
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
        int
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
            dict
        ):
            continue

        searchable_text = json.dumps(
            record,
            ensure_ascii=False
        ).lower()

        score = sum(
            searchable_text.count(term)
            for term in query_terms
        )

        if score > 0:

            scored.append(
                (
                    score,
                    record
                )
            )

    scored.sort(
        key=lambda item: item[0],
        reverse=True
    )

    results = []

    for rank, (
        score,
        record
    ) in enumerate(
        scored[:limit],
        start=1
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


def build_evidence_context(
    query: str,
    top_k: int = 5
):
    """
    Build provenance-preserving evidence context.
    """

    results = semantic_search(
        query=query,
        top_k=top_k
    )

    contexts = []

    for result in results:

        contexts.append({

            "rank": result["rank"],

            "similarity": result["similarity"],

            "email_id": result["email_id"],

            "chunk_id": result["chunk_id"],

            "source_file": result["source_file"],

            "text": result["text"],

            "memory": result["memory"],

            "provenance": {

                "email_id": result["email_id"],

                "chunk_id": result["chunk_id"],

                "source_file": result["source_file"],

            },

        })

    return {

        "query": query,

        "retrieval_method": (
            "semantic_cosine_similarity"
        ),

        "top_k": top_k,

        "results": contexts,

    }


def statistics():

    return {

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

    }
