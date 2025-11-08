import pandas as pd
import uuid
from difflib import SequenceMatcher

def cluster_fragments(fragments, score_threshold=0.85):
    """
    Performs simple probabilistic clustering (fuzzy linking)
    based on name/email similarity.

    FIXED:
    - Ensures each fragment is correctly linked to an entity
    - Properly updates DataFrame with entity_id and confidence
    - Keeps mapping index aligned with fragments list
    """

    df = pd.DataFrame(fragments)
    df["entity_id"] = None
    df["score"] = 0.0

    if "value" not in df.columns:
        return {}, df

    entity_groups = {}
    mapping = {}
    entity_counter = 0

    for i, row in df.iterrows():
        val = str(row.get("value", "")).lower().strip()
        if not val:
            continue

        assigned = False

        # Match with existing entities
        for eid, group in entity_groups.items():
            existing_vals = [v["value"].lower().strip() for v in group["members"]]
            similarities = [SequenceMatcher(None, val, ev).ratio() for ev in existing_vals]
            max_similarity = max(similarities) if similarities else 0

            if max_similarity >= score_threshold:
                df.at[i, "entity_id"] = eid
                df.at[i, "score"] = round(max_similarity, 2)
                group["members"].append(row.to_dict())

                mapping[i] = {
                    "entity_id": eid,
                    "confidence": round(max_similarity, 2)
                }
                assigned = True
                break

        # Create new entity if no match found
        if not assigned:
            entity_counter += 1
            eid = f"E-{entity_counter:06d}"
            df.at[i, "entity_id"] = eid
            df.at[i, "score"] = 1.0

            entity_groups[eid] = {
                "entity_id": eid,
                "members": [row.to_dict()]
            }

            mapping[i] = {
                "entity_id": eid,
                "confidence": 1.0
            }

    # Clean up dataframe for saving
    df.fillna({"entity_id": "N/A", "score": 0.0}, inplace=True)

    return mapping, df


def get_cluster_summary(mapping, df):
    """
    Generate a summary of clustered entities.
    FIXED:
    - Properly shows fragment_count, names, emails
    - Sorts by entity_id for consistency
    """
    summary = []

    if "entity_id" not in df.columns:
        df["entity_id"] = df.index.map(lambda i: mapping.get(i, {}).get("entity_id"))

    unique_entities = set([m["entity_id"] for m in mapping.values() if "entity_id" in m])

    for eid in sorted(unique_entities):
        subset = df[df["entity_id"] == eid]
        if subset.empty:
            continue

        names = "N/A"
        emails = "N/A"

        if "type" in subset.columns:
            name_vals = subset.loc[subset["type"] == "PERSON", "value"].dropna().unique()
            email_vals = subset.loc[subset["type"] == "EMAIL_ADDRESS", "value"].dropna().unique()
            if len(name_vals) > 0:
                names = ", ".join(name_vals[:3])
            if len(email_vals) > 0:
                emails = ", ".join(email_vals[:3])

        avg_conf = round(subset["score"].mean(), 2) if "score" in subset.columns else 1.0

        summary.append({
            "entity_id": eid,
            "fragment_count": len(subset),
            "names": names,
            "emails": emails,
            "avg_confidence": avg_conf
        })

    summary_df = pd.DataFrame(summary)
    return summary_df.sort_values("entity_id").reset_index(drop=True)
