"""Read-only adapter for the vendored NIST CSF 2.0 OSCAL catalog.

The source document is intentionally retained unchanged in
``profiles/nist-csf-2.0-catalog.json``.  This module exposes only the small,
stable hierarchy the local UI needs; it does not reinterpret official outcome
text as executable product behavior.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


CATALOG_PATH = Path(__file__).resolve().parent / "profiles" / "nist-csf-2.0-catalog.json"
EXPECTED_FUNCTION_COUNT = 6
EXPECTED_CATEGORY_COUNT = 22
EXPECTED_SUBCATEGORY_COUNT = 106

# Product-authored labels.  They supplement, rather than alter, the official
# NIST outcome statements and are shared by every product surface that needs a
# compact name for a CSF Subcategory.
SUBCATEGORY_SHORT_DESCRIPTIONS = {
    "GV.OC-01": "Mission statement", "GV.OC-02": "Stakeholder needs", "GV.OC-03": "Requirements", "GV.OC-04": "Critical services", "GV.OC-05": "External dependencies",
    "GV.OV-01": "Risk management review", "GV.OV-02": "Strategy review", "GV.OV-03": "Risk management performance", "GV.PO-01": "Cybersecurity policy", "GV.PO-02": "Policy updates",
    "GV.RM-01": "Risk objectives", "GV.RM-02": "Risk appetite", "GV.RM-03": "Enterprise risk integration", "GV.RM-04": "Response options", "GV.RM-05": "Communication paths", "GV.RM-06": "Risk assessment method", "GV.RM-07": "Positive risk opportunities",
    "GV.RR-01": "Leadership accountability", "GV.RR-02": "Roles and responsibilities", "GV.RR-03": "Resources", "GV.RR-04": "Human resources practices",
    "GV.SC-01": "Supply-chain program", "GV.SC-02": "Supply-chain roles", "GV.SC-03": "Supply-chain risk integration", "GV.SC-04": "Supplier criticality", "GV.SC-05": "Supplier requirements", "GV.SC-06": "Supplier due diligence", "GV.SC-07": "Supplier monitoring", "GV.SC-08": "Supplier incident involvement", "GV.SC-09": "Supply-chain life-cycle practices", "GV.SC-10": "Post-relationship planning",
    "ID.AM-01": "Hardware inventory", "ID.AM-02": "Software and services inventory", "ID.AM-03": "Network and data flows", "ID.AM-04": "Supplier services inventory", "ID.AM-05": "Asset criticality", "ID.AM-07": "Data inventory", "ID.AM-08": "Asset life cycle",
    "ID.IM-01": "Evaluation findings", "ID.IM-02": "Exercise findings", "ID.IM-03": "Operational lessons", "ID.IM-04": "Plan improvements",
    "ID.RA-01": "Vulnerability identification", "ID.RA-02": "Threat intelligence", "ID.RA-03": "Threat identification", "ID.RA-04": "Risk analysis", "ID.RA-05": "Risk prioritization", "ID.RA-06": "Risk response", "ID.RA-07": "Change and exception risk", "ID.RA-08": "Vulnerability disclosures", "ID.RA-09": "Technology authenticity", "ID.RA-10": "Supplier risk assessment",
    "PR.AA-01": "Identity and credential management", "PR.AA-02": "Identity proofing", "PR.AA-03": "Authentication", "PR.AA-04": "Identity assertions", "PR.AA-05": "Access permissions", "PR.AA-06": "Physical access",
    "PR.AT-01": "General awareness and training", "PR.AT-02": "Specialized training",
    "PR.DS-01": "Data at rest", "PR.DS-02": "Data in transit", "PR.DS-10": "Data in use", "PR.DS-11": "Data backups",
    "PR.IR-01": "Network protection", "PR.IR-02": "Environmental protection", "PR.IR-03": "Resilience mechanisms", "PR.IR-04": "Resource capacity",
    "PR.PS-01": "Configuration management", "PR.PS-02": "Software maintenance", "PR.PS-03": "Hardware maintenance", "PR.PS-04": "Log records", "PR.PS-05": "Unauthorized software prevention", "PR.PS-06": "Secure software development",
    "DE.AE-02": "Event analysis", "DE.AE-03": "Event correlation", "DE.AE-04": "Impact and scope", "DE.AE-06": "Event information sharing", "DE.AE-07": "Threat context", "DE.AE-08": "Incident declaration",
    "DE.CM-01": "Network monitoring", "DE.CM-02": "Physical environment monitoring", "DE.CM-03": "Personnel monitoring", "DE.CM-06": "Provider monitoring", "DE.CM-09": "Technology monitoring",
    "RS.AN-03": "Incident investigation", "RS.AN-06": "Investigation records", "RS.AN-07": "Incident data", "RS.AN-08": "Incident scope", "RS.CO-02": "Incident notifications", "RS.CO-03": "Incident communications", "RS.MA-01": "Response plan", "RS.MA-02": "Incident triage", "RS.MA-03": "Incident prioritization", "RS.MA-04": "Incident escalation", "RS.MA-05": "Recovery initiation", "RS.MI-01": "Containment", "RS.MI-02": "Eradication",
    "RC.CO-03": "Recovery communications", "RC.CO-04": "Public recovery updates", "RC.RP-01": "Recovery plan", "RC.RP-02": "Recovery priorities", "RC.RP-03": "Restoration asset verification", "RC.RP-04": "Post-incident operations", "RC.RP-05": "Restoration verification", "RC.RP-06": "Recovery completion",
}


def _part_prose(parts: List[Dict[str, Any]], name: str = "statement") -> str:
    for part in parts or []:
        if str(part.get("name") or "").strip().lower() == name:
            return str(part.get("prose") or "").strip()
    return ""


def _part_prose_list(parts: List[Dict[str, Any]], name: str) -> List[str]:
    """Return ordered prose parts without rewording the official catalog."""
    return [
        str(part.get("prose") or "").strip()
        for part in parts or []
        if str(part.get("name") or "").strip().lower() == name and str(part.get("prose") or "").strip()
    ]


def _is_withdrawn(item: Dict[str, Any]) -> bool:
    return any(
        str(prop.get("name") or "").strip().lower() == "status"
        and str(prop.get("value") or "").strip().lower() == "withdrawn"
        for prop in item.get("props") or []
    )


def load_official_catalog(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load and validate the official CSF 2.0 hierarchy from vendored OSCAL."""
    source_path = Path(path or CATALOG_PATH)
    with source_path.open("r", encoding="utf-8") as handle:
        document = json.load(handle)

    catalog = document.get("catalog") or {}
    metadata = catalog.get("metadata") or {}
    functions: List[Dict[str, Any]] = []
    category_count = 0
    subcategory_count = 0

    for function in catalog.get("groups") or []:
        if str(function.get("class") or "").strip().lower() != "function":
            continue
        categories: List[Dict[str, Any]] = []
        for category in function.get("controls") or []:
            if str(category.get("class") or "").strip().lower() != "category" or _is_withdrawn(category):
                continue
            subcategories: List[Dict[str, Any]] = []
            for subcategory in category.get("controls") or []:
                if str(subcategory.get("class") or "").strip().lower() != "subcategory" or _is_withdrawn(subcategory):
                    continue
                subcategories.append(
                    {
                        "id": str(subcategory.get("id") or "").strip(),
                        "title": str(subcategory.get("title") or "").strip(),
                        "short_description": SUBCATEGORY_SHORT_DESCRIPTIONS.get(str(subcategory.get("id") or "").strip(), ""),
                        "outcome": _part_prose(subcategory.get("parts") or []),
                        "implementation_examples": _part_prose_list(subcategory.get("parts") or [], "example"),
                    }
                )
            subcategory_count += len(subcategories)
            categories.append(
                {
                    "id": str(category.get("id") or "").strip(),
                    "title": str(category.get("title") or "").strip(),
                    "outcome": _part_prose(category.get("parts") or []),
                    "subcategories": subcategories,
                }
            )
        category_count += len(categories)
        functions.append(
            {
                "id": str(function.get("id") or "").strip(),
                "title": str(function.get("title") or "").strip(),
                "outcome": _part_prose(function.get("parts") or [], "overview"),
                "categories": categories,
            }
        )

    if len(functions) != EXPECTED_FUNCTION_COUNT:
        raise ValueError(f"Expected {EXPECTED_FUNCTION_COUNT} CSF Functions, found {len(functions)}.")
    if category_count != EXPECTED_CATEGORY_COUNT:
        raise ValueError(f"Expected {EXPECTED_CATEGORY_COUNT} CSF Categories, found {category_count}.")
    if subcategory_count != EXPECTED_SUBCATEGORY_COUNT:
        raise ValueError(f"Expected {EXPECTED_SUBCATEGORY_COUNT} CSF Subcategories, found {subcategory_count}.")
    if len(SUBCATEGORY_SHORT_DESCRIPTIONS) != subcategory_count:
        raise ValueError(f"Expected {subcategory_count} product short descriptions, found {len(SUBCATEGORY_SHORT_DESCRIPTIONS)}.")

    return {
        "source_path": str(source_path),
        "catalog_title": str(metadata.get("title") or "NIST Cybersecurity Framework 2.0"),
        "catalog_version": str(metadata.get("version") or ""),
        "functions": functions,
    }


def find_official_subcategory(identifier: str, path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Return one official subcategory with its containing Function/Category."""
    target = str(identifier or "").strip().upper()
    for function in load_official_catalog(path).get("functions") or []:
        for category in function.get("categories") or []:
            for subcategory in category.get("subcategories") or []:
                if subcategory.get("id", "").upper() == target:
                    return {
                        **subcategory,
                        "function_id": function["id"],
                        "function_title": function["title"],
                        "category_id": category["id"],
                        "category_title": category["title"],
                    }
    return None
