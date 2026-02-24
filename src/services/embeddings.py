import os
from openai import OpenAI
from pinecone import Pinecone, ServerlessSpec

oai = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
pc  = Pinecone(api_key=os.environ["PINECONE_API_KEY"])

index = pc.Index("fintellect-docs")

def embed(text: str) -> list[float]:
    res = oai.embeddings.create(input=text, model="text-embedding-3-small")
    return res.data[0].embedding

# Upsert a document chunk
chunk = "Revenue increased 18% YoY driven by cloud segment growth."
index.upsert(vectors=[{
    "id": "chunk-001",
    "values": embed(chunk),
    "metadata": {"text": chunk, "ticker": "MSFT", "filing": "10-K-2024"}
}])

# Semantic search
query = "What drove revenue growth?"
matches = index.query(vector=embed(query), top_k=5, include_metadata=True)

for m in matches["matches"]:
    print(f"[{m['score']:.3f}] {m['metadata']['text']}")