"""Product assessment metadata for the Single-PC CSF Profile.

The official outcome and implementation examples stay in ``csf_catalog``.
This module adds only product decisions: how a learner can assess an outcome
on one Windows PC and whether a supporting note is required.  The method is
not a NIST classification and it does not establish CSF compliance.
"""

from typing import Dict

from csf_catalog import load_official_catalog


ASSESSMENT_METHODS = {"evidence", "attestation", "review", "hybrid"}

# Apply a deliberately small, reviewable method rule to each active category.
# Individual subcategories inherit their category's method until a justified
# exception is added here.  This avoids inventing Windows evidence coverage.
_METHOD_BY_CATEGORY = {
    "GV.OC": "review",
    "GV.OV": "review",
    "GV.PO": "review",
    "GV.RM": "review",
    "GV.RR": "review",
    "GV.SC": "review",
    "ID.AM": "evidence",
    "ID.IM": "review",
    "ID.RA": "hybrid",
    "PR.AA": "hybrid",
    "PR.AT": "attestation",
    "PR.DS": "hybrid",
    "PR.IR": "hybrid",
    "PR.PS": "hybrid",
    "DE.AE": "hybrid",
    "DE.CM": "evidence",
    "RS.AN": "review",
    "RS.CO": "review",
    "RS.MA": "review",
    "RS.MI": "hybrid",
    "RC.CO": "review",
    "RC.RP": "hybrid",
}

_RESEARCH_GUIDANCE = {
    "evidence": "Review the local Windows evidence shown here. Confirm its collection time and limitations before choosing a Profile state.",
    "attestation": "Confirm this outcome with the person responsible for this PC. Record the basis for the answer rather than assuming it from a setting.",
    "review": "Review the relevant plan, record, agreement, or decision. Record where it was checked and why the chosen Profile state is accurate.",
    "hybrid": "Review the local Windows evidence and confirm the context with the person responsible for this PC. Record the basis for the chosen Profile state.",
}


def _active_subcategories() -> Dict[str, str]:
    catalog = load_official_catalog()
    return {
        subcategory["id"]: category["id"]
        for function in catalog["functions"]
        for category in function["categories"]
        for subcategory in category["subcategories"]
    }


_ACTIVE_SUBCATEGORY_CATEGORIES = _active_subcategories()
_MISSING_CATEGORY_METHODS = set(_ACTIVE_SUBCATEGORY_CATEGORIES.values()).difference(_METHOD_BY_CATEGORY)
if _MISSING_CATEGORY_METHODS:
    raise ValueError(f"Assessment methods are missing active CSF Categories: {sorted(_MISSING_CATEGORY_METHODS)}")


SUBCATEGORY_PROFILE_METADATA_EN_US = {
    subcategory_id: {
        "assessment_method": _METHOD_BY_CATEGORY[category_id],
        "research_guidance": _RESEARCH_GUIDANCE[_METHOD_BY_CATEGORY[category_id]],
        "supporting_note_required": _METHOD_BY_CATEGORY[category_id] in {"review", "hybrid"},
    }
    for subcategory_id, category_id in sorted(_ACTIVE_SUBCATEGORY_CATEGORIES.items())
}
