VERDICT_PHRASING = {
    "true_positive": "was found to be malicious",
    "false_positive": "was assessed as non-malicious",
}

IOC_LABELS = {"ip": "IP address", "hash": "file hash", "domain": "domain", "url": "URL"}


def generate_soc_summary(ioc_type: str, ioc_value: str, verdict_data: dict) -> str:
    verdict = verdict_data["verdict"]
    confidence = verdict_data["confidence"]
    reasoning = verdict_data["reasoning"]
    phrasing = VERDICT_PHRASING[verdict]
    ioc_label = IOC_LABELS.get(ioc_type, "indicator")

    summary = f"Upon investigation of the {ioc_label} {ioc_value}, it {phrasing}. "

    if reasoning["malicious_sources"]:
        summary += f"Detections were confirmed by: {', '.join(reasoning['malicious_sources'])}. "
    elif reasoning["clean_sources"]:
        summary += f"No detections across: {', '.join(reasoning['clean_sources'])}. "

    summary += f"Composite risk score: {reasoning['composite_score']:.0f}/100 (confidence: {confidence}). "

    if verdict == "true_positive":
        summary += "Recommend containment/blocking action per incident response procedures."
    else:
        summary += "No further action required at this time."

    if confidence == "low":
        summary += " Note: signal strength was low — recommend manual analyst validation before closing."

    return summary