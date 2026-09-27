"""Product-authored capability prerequisites between CSF 2.0 outcomes.

Unlike ``csf_information_flows``, these edges do not describe a record moving
from one outcome to another.  They describe a capability that must exist, or
substantially exist, before a dependent outcome can be represented as achieved.
They are not an official NIST implementation sequence.
"""

from typing import Dict, List


# ``hard_gate`` blocks a fully-implemented claim for the dependent outcome.
# ``partial_gate`` limits the claim in contexts where the prerequisite applies.
# ``supporting_capability`` informs planning but is not a completion blocker.
CAPABILITY_DEPENDENCIES: List[Dict[str, str]] = [
    {
        "prerequisite_subcategory_id": "GV.RM-03",
        "dependent_subcategory_id": "GV.SC-03",
        "dependency_strength": "partial_gate",
        "rationale": "Integrating supply-chain risk into enterprise risk management requires an enterprise-risk-management integration process, although both outcomes may mature together.",
    },
    {
        "prerequisite_subcategory_id": "GV.RR-01",
        "dependent_subcategory_id": "GV.RR-02",
        "dependency_strength": "supporting_capability",
        "rationale": "Accountable leadership supports establishing, enforcing, and reviewing cybersecurity roles and authorities.",
    },
    {
        "prerequisite_subcategory_id": "GV.RR-01",
        "dependent_subcategory_id": "GV.RR-03",
        "dependency_strength": "supporting_capability",
        "rationale": "Accountable leadership supports allocating resources consistent with cybersecurity risk direction and responsibilities.",
    },
    {
        "prerequisite_subcategory_id": "GV.RR-01",
        "dependent_subcategory_id": "GV.RR-04",
        "dependency_strength": "supporting_capability",
        "rationale": "Leadership expectations support embedding cybersecurity responsibility and culture in human resources practices.",
    },
    {
        "prerequisite_subcategory_id": "GV.RR-01",
        "dependent_subcategory_id": "GV.PO-01",
        "dependency_strength": "supporting_capability",
        "rationale": "Leadership accountability supports establishing, communicating, and enforcing cybersecurity policy.",
    },
    {
        "prerequisite_subcategory_id": "GV.RR-02",
        "dependent_subcategory_id": "PR.AT-02",
        "dependency_strength": "hard_gate",
        "rationale": "Specialized training cannot be fully established until the specialized cybersecurity roles that require it are identified.",
    },
    {
        "prerequisite_subcategory_id": "GV.RR-02",
        "dependent_subcategory_id": "RS.MA-01",
        "dependency_strength": "partial_gate",
        "rationale": "Executing an incident response plan requires assigned internal and third-party responsibilities for the applicable response work.",
    },
    {
        "prerequisite_subcategory_id": "GV.RR-02",
        "dependent_subcategory_id": "RC.RP-01",
        "dependency_strength": "partial_gate",
        "rationale": "Executing recovery work requires people with the necessary recovery responsibilities and authorizations.",
    },
    {
        "prerequisite_subcategory_id": "GV.RR-04",
        "dependent_subcategory_id": "PR.AT-01",
        "dependency_strength": "supporting_capability",
        "rationale": "Human resources practices support onboarding, refresher, and accountability processes for general cybersecurity awareness.",
    },
    {
        "prerequisite_subcategory_id": "GV.RR-04",
        "dependent_subcategory_id": "PR.AT-02",
        "dependency_strength": "supporting_capability",
        "rationale": "Human resources practices support assigning, tracking, and refreshing training for specialized roles.",
    },
    {
        "prerequisite_subcategory_id": "GV.PO-01",
        "dependent_subcategory_id": "PR.AT-01",
        "dependency_strength": "supporting_capability",
        "rationale": "General awareness is more actionable when personnel have cybersecurity policy and acceptable-use expectations to follow.",
    },
    {
        "prerequisite_subcategory_id": "PR.AA-01",
        "dependent_subcategory_id": "PR.AA-02",
        "dependency_strength": "hard_gate",
        "rationale": "Proofing and binding identities to credentials requires an identity and credential-management capability.",
    },
    {
        "prerequisite_subcategory_id": "PR.AA-01",
        "dependent_subcategory_id": "PR.AA-05",
        "dependency_strength": "hard_gate",
        "rationale": "Access permissions cannot be fully managed and enforced without managed identities for users, services, and hardware.",
    },
    {
        "prerequisite_subcategory_id": "PR.AA-02",
        "dependent_subcategory_id": "PR.AA-03",
        "dependency_strength": "hard_gate",
        "rationale": "Authentication depends on identities being reliably proofed and bound to the credentials used to authenticate them.",
    },
    {
        "prerequisite_subcategory_id": "PR.AA-03",
        "dependent_subcategory_id": "PR.AA-04",
        "dependency_strength": "partial_gate",
        "rationale": "Where identity assertions convey authentication information, assertion protection and verification depend on a functioning authentication context.",
    },
    {
        "prerequisite_subcategory_id": "PR.AA-05",
        "dependent_subcategory_id": "PR.DS-10",
        "dependency_strength": "supporting_capability",
        "rationale": "Access permissions support protecting data in use from access by other users and processes, but data-in-use protections also include safeguards beyond access control.",
    },
    {
        "prerequisite_subcategory_id": "PR.IR-02",
        "dependent_subcategory_id": "PR.IR-03",
        "dependency_strength": "supporting_capability",
        "rationale": "Protection from environmental threats supports resilience in adverse situations, although resilience can also be achieved through mechanisms unrelated to environmental protection.",
    },
    {
        "prerequisite_subcategory_id": "PR.AA-03",
        "dependent_subcategory_id": "PR.AA-05",
        "dependency_strength": "hard_gate",
        "rationale": "A fully implemented access-permission outcome requires reliable authentication of the user, service, or hardware receiving the permission.",
    },
    {
        "prerequisite_subcategory_id": "PR.AA-06",
        "dependent_subcategory_id": "DE.CM-02",
        "dependency_strength": "supporting_capability",
        "rationale": "Physical access controls and records provide the mechanisms and evidence that physical-environment monitoring reviews for adverse events.",
    },
    {
        "prerequisite_subcategory_id": "PR.PS-01",
        "dependent_subcategory_id": "PR.PS-05",
        "dependency_strength": "supporting_capability",
        "rationale": "Configuration-management practices support consistent allowlisting, installation restrictions, and other controls that prevent unauthorized software execution.",
    },
    {
        "prerequisite_subcategory_id": "PR.IR-04",
        "dependent_subcategory_id": "PR.IR-03",
        "dependency_strength": "supporting_capability",
        "rationale": "Adequate resource capacity supports resilience mechanisms during normal operation and adverse conditions.",
    },
    {
        "prerequisite_subcategory_id": "PR.DS-11",
        "dependent_subcategory_id": "RC.RP-03",
        "dependency_strength": "hard_gate",
        "rationale": "Restoration assets must exist before their integrity can be verified for restoration use.",
    },
    {
        "prerequisite_subcategory_id": "RC.RP-03",
        "dependent_subcategory_id": "RC.RP-05",
        "dependency_strength": "hard_gate",
        "rationale": "Assets should be verified before they are used for restoration and before restored operation is confirmed.",
    },
    {
        "prerequisite_subcategory_id": "DE.AE-08",
        "dependent_subcategory_id": "RS.MA-01",
        "dependency_strength": "hard_gate",
        "rationale": "The incident response plan is executed after an adverse event meets the defined incident criteria and an incident is declared.",
    },
    {
        "prerequisite_subcategory_id": "RS.MA-03",
        "dependent_subcategory_id": "RS.MA-04",
        "dependency_strength": "partial_gate",
        "rationale": "Escalation decisions use the incident's established category and priority when those details are applicable.",
    },
    {
        "prerequisite_subcategory_id": "RS.MA-03",
        "dependent_subcategory_id": "RS.MA-05",
        "dependency_strength": "partial_gate",
        "rationale": "Applying recovery-initiation criteria uses the incident's category and priority when those details affect the decision.",
    },
    {
        "prerequisite_subcategory_id": "RS.MA-05",
        "dependent_subcategory_id": "RC.RP-01",
        "dependency_strength": "hard_gate",
        "rationale": "The recovery portion of the incident response plan is executed once recovery is initiated from the incident response process.",
    },
]
