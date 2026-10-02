"""Reviewed product-authored directions for selected control-to-CSF mappings.

The official informative-reference workbook establishes that a control and CSF
Subcategory are related.  It does not establish direction.  These records
separately capture the product's reviewed explanation of whether a control
produces information for the outcome, consumes information from it, enables a
capability, or is context only.  They do not alter the official mapping.
"""

from typing import Dict, List


NIST_SP_800_53_R5_2_0 = "nist-sp-800-53-r5.2.0"


# Populate only mappings that have been specifically reviewed.  Unlisted
# informative mappings deliberately remain unclassified.
CONTROL_MAPPING_RELATIONSHIPS: List[Dict[str, str]] = [
    {
        "framework_id": NIST_SP_800_53_R5_2_0,
        "control_id": "PM-11",
        "subcategory_id": "GV.OC-01",
        "relationship_role": "produces_outcome_information",
        "information_id": "organizational_mission",
        "relationship_scope": "direct",
        "rationale": "Defining and reviewing mission and business processes produces the current mission information this outcome needs to inform cybersecurity decisions.",
    },
    {
        "framework_id": NIST_SP_800_53_R5_2_0,
        "control_id": "PM-09",
        "subcategory_id": "GV.OC-02",
        "relationship_role": "context_only",
        "information_id": "",
        "relationship_scope": "indirect",
        "rationale": "PM-09 requires a security and privacy risk strategy, but does not expressly require identifying or using stakeholder cybersecurity needs.",
    },
    {
        "framework_id": NIST_SP_800_53_R5_2_0,
        "control_id": "PM-18",
        "subcategory_id": "GV.OC-02",
        "relationship_role": "context_only",
        "information_id": "",
        "relationship_scope": "indirect",
        "rationale": "PM-18 requires a privacy program plan, but does not expressly require identifying or using stakeholder cybersecurity needs.",
    },
    {
        "framework_id": NIST_SP_800_53_R5_2_0,
        "control_id": "PM-30",
        "subcategory_id": "GV.OC-02",
        "relationship_role": "context_only",
        "information_id": "",
        "relationship_scope": "indirect",
        "rationale": "PM-30 requires a supply-chain risk management strategy, but does not expressly require identifying or using stakeholder cybersecurity needs.",
    },
    {
        "framework_id": NIST_SP_800_53_R5_2_0,
        "control_id": "SR-03",
        "subcategory_id": "GV.OC-02",
        "relationship_role": "context_only",
        "information_id": "",
        "relationship_scope": "indirect",
        "rationale": "Supply-chain controls and processes address weaknesses and controls, not the identification or understanding of stakeholders and their needs.",
    },
    {
        "framework_id": NIST_SP_800_53_R5_2_0,
        "control_id": "SR-05",
        "subcategory_id": "GV.OC-02",
        "relationship_role": "context_only",
        "information_id": "",
        "relationship_scope": "indirect",
        "rationale": "SR-05 requires acquisition strategies and methods for supply-chain risks, but does not expressly require identifying or using stakeholder cybersecurity needs.",
    },
    {
        "framework_id": NIST_SP_800_53_R5_2_0,
        "control_id": "SR-06",
        "subcategory_id": "GV.OC-02",
        "relationship_role": "context_only",
        "information_id": "",
        "relationship_scope": "indirect",
        "rationale": "SR-06 requires supplier risk assessments and reviews, but does not expressly require identifying or using stakeholder cybersecurity needs.",
    },
    {
        "framework_id": NIST_SP_800_53_R5_2_0,
        "control_id": "SR-08",
        "subcategory_id": "GV.OC-02",
        "relationship_role": "context_only",
        "information_id": "",
        "relationship_scope": "indirect",
        "rationale": "SR-08 requires notification agreements, but does not expressly require identifying or using stakeholder cybersecurity needs.",
    },
]
