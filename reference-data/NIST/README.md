# NIST reference-data provenance

These source artifacts support the local, development-only import of NIST SP
800-53 Rev. 5.2.0 controls and the final NIST CSF 2.0 informative-reference
mapping. They are retained with the project rather than treated as temporary
downloads so a future import can be reproduced and reviewed.

| Artifact | Purpose | SHA-256 |
| --- | --- | --- |
| `csf-2.0-informative-references.xlsx` | CSF 2.0 Informative References workbook; only `SP 800-53 Rev 5.2.0` references are imported | `30DABC979A7F19D213D1F9C0FD57DEC700E467F4E4BF3628E755E6CCD1E18E1F` |
| `NIST_SP-800-53_rev5_catalog.json` | Official NIST OSCAL control catalog, metadata version 5.2.0 | `01F37CF90EA99D92242C936CBFBDEBCC338EEF1F71454E2ACAC36CC56E9BC062` |

Retrieved: 2026-09-20.

Authoritative source pages:

- NIST CSF Informative References: <https://www.nist.gov/cyberframework/informative-references>
- NIST SP 800-53 downloads: <https://csrc.nist.gov/projects/risk-management/sp800-53-controls/downloads>
- OSCAL catalog source: <https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json>

The importer is intentionally scoped to the final 5.2.0 references, validates
each imported control against the catalog, and skips non-control family labels
in the workbook (`CP`, `IR`, and `PT`).
