from pymongo import MongoClient
from collections import defaultdict

# === MongoDB Setup ===
client = MongoClient("mongodb+srv://rskissan:HZIXkw1D5XOUxaS2@osintunctruc.p5itk5s.mongodb.net/?retryWrites=true&w=majority")
db = client["osint_db"]

# === Grouped Detokenization Function ===
def detokenize_grouped_entities(entities):
    grouped = defaultdict(list)
    buffer = ""
    last_label = None

    for ent in entities:
        token = ent["text"]
        label = ent["label"].upper()

        if token.startswith("##"):
            buffer += token[2:]
        else:
            if buffer and last_label:
                grouped[last_label].append(buffer)
            buffer = token
            last_label = label

    if buffer and last_label:
        grouped[last_label].append(buffer)

    return {k: list(set(v)) for k, v in grouped.items()}

# === Collections to Patch ===
collections_to_patch = [
    "enriched_newsapi_data",
    "enriched_reddit_data",
    "enriched_rss_data"
]

# === Patch Loop ===
for col_name in collections_to_patch:
    col = db[col_name]
    print(f"🔄 Patching collection: {col_name}")

    updated_count = 0
    for doc in col.find():
        if "entity_summary" not in doc:
            try:
                summary = detokenize_grouped_entities(doc["entities"])
                col.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {"entity_summary": summary}}
                )
                updated_count += 1
            except Exception as e:
                print(f"⚠️ Error processing doc {doc['_id']}: {e}")

    print(f"✅ Updated {updated_count} documents in {col_name}")
