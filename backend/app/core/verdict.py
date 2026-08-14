def determine_verdict(enrichment_results: list[dict], total_sources_attempted: int) -> dict:
    """
    Takes the raw list of per-source results (each with source/score/verdict)
    and produces one combined true_positive/false_positive verdict.

    total_sources_attempted = how many sources were even queried (including
    ones that errored out). This lets us downgrade confidence when too few
    sources actually responded, instead of overstating "high confidence"
    off a single working source.
    """
    valid_results = [r for r in enrichment_results if r["verdict"] in ("clean", "suspicious", "malicious")]

    if not valid_results:
        return {
            "verdict": "false_positive",
            "confidence": "low",
            "reasoning": {
                "summary": "No sources returned usable data — unable to confirm any risk.",
                "malicious_sources": [],
                "clean_sources": [],
                "composite_score": 0,
                "sources_responded": 0,
                "sources_attempted": total_sources_attempted,
            },
        }

    malicious_hits = [r for r in valid_results if r["verdict"] == "malicious"]
    suspicious_hits = [r for r in valid_results if r["verdict"] == "suspicious"]
    clean_hits = [r for r in valid_results if r["verdict"] == "clean"]
    total_valid = len(valid_results)

    composite_score = round(sum(r["score"] for r in valid_results) / total_valid, 2)

    if len(malicious_hits) >= 2:
        verdict = "true_positive"
        confidence = "high"
        reason = f"{len(malicious_hits)}/{total_valid} sources independently flagged as malicious"

    elif len(malicious_hits) == 1 and composite_score > 60:
        verdict = "true_positive"
        confidence = "medium"
        reason = f"1 source flagged malicious with elevated composite score ({composite_score:.0f})"

    elif len(suspicious_hits) >= 1 and len(clean_hits) == 0 and composite_score > 50:
        verdict = "true_positive"
        confidence = "low"
        reason = "Suspicious signals with no clean confirmation — leaning malicious, recommend review"

    elif len(clean_hits) == total_valid:
        verdict = "false_positive"
        confidence = "high"
        reason = "All queried sources returned clean/no detections"

    else:
        verdict = "false_positive"
        confidence = "low"
        reason = "Insufficient or conflicting data — leaning benign, recommend manual review"

    # Downgrade confidence if fewer than half the attempted sources actually responded
    response_rate = total_valid / total_sources_attempted if total_sources_attempted else 0
    if response_rate < 0.5 and confidence == "high":
        confidence = "medium"
        reason += f" (note: only {total_valid}/{total_sources_attempted} sources responded — confidence capped)"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": {
            "summary": reason,
            "malicious_sources": [r["source"] for r in malicious_hits],
            "clean_sources": [r["source"] for r in clean_hits],
            "composite_score": composite_score,
            "sources_responded": total_valid,
            "sources_attempted": total_sources_attempted,
        },
    }