import unittest

import csf_catalog
from csf_guidance import PLAIN_ENGLISH_GUIDANCE_EN_US, PRODUCT_EXAMPLES_EN_US
from csf_profile import SUBCATEGORY_PROFILE_METADATA_EN_US
import codex_monitor_ui as ui


class OfficialCsfCatalogTests(unittest.TestCase):
    def test_vendored_catalog_has_complete_csf_2_0_hierarchy(self) -> None:
        catalog = csf_catalog.load_official_catalog()
        self.assertEqual(["GV", "ID", "PR", "DE", "RS", "RC"], [item["id"] for item in catalog["functions"]])
        self.assertEqual(22, sum(len(item["categories"]) for item in catalog["functions"]))
        self.assertEqual(106, sum(len(category["subcategories"]) for item in catalog["functions"] for category in item["categories"]))
        catalog_ids = {subcategory["id"] for function in catalog["functions"] for category in function["categories"] for subcategory in category["subcategories"]}
        self.assertEqual(catalog_ids, set(PLAIN_ENGLISH_GUIDANCE_EN_US))
        self.assertEqual(catalog_ids, set(SUBCATEGORY_PROFILE_METADATA_EN_US))
        self.assertTrue(all(text.strip() for text in PLAIN_ENGLISH_GUIDANCE_EN_US.values()))
        self.assertEqual(catalog_ids, set(PRODUCT_EXAMPLES_EN_US))
        self.assertTrue(all(examples for examples in PRODUCT_EXAMPLES_EN_US.values()))
        self.assertEqual(
            PLAIN_ENGLISH_GUIDANCE_EN_US["GV.OC-01"],
            "Make sure the organization’s mission is documented, shared, and understood by the people responsible for cybersecurity risk management.",
        )
        self.assertEqual(
            {"evidence", "attestation", "review", "hybrid"},
            {metadata["assessment_method"] for metadata in SUBCATEGORY_PROFILE_METADATA_EN_US.values()},
        )

    def test_de_cm_uses_official_outcome_text(self) -> None:
        outcome = csf_catalog.find_official_subcategory("DE.CM-09")
        self.assertIsNotNone(outcome)
        assert outcome is not None
        self.assertEqual("DE", outcome["function_id"])
        self.assertEqual("DE.CM", outcome["category_id"])
        self.assertTrue(outcome["outcome"])
        self.assertTrue(outcome["implementation_examples"])

    def test_unknown_subcategory_is_not_invented(self) -> None:
        self.assertIsNone(csf_catalog.find_official_subcategory("LOCAL.DE.01.01"))

    def test_explorer_uses_direct_url_selection_and_does_not_claim_unmapped_coverage(self) -> None:
        model = {
            "task_job_health": {
                "groups": {"detect": ["Codex IOC Daily Scan"]},
                "by_name": {
                    "Codex IOC Daily Scan": {
                        "Name": "Codex IOC Daily Scan",
                        "Installed": True,
                        "Enabled": True,
                        "State": "Ready",
                        "LastTaskResult": 0,
                        "LastRunTime": "2026-09-14T02:00:00Z",
                        "NextRunTime": "2026-09-15T02:00:00Z",
                    }
                },
            }
        }
        category_page = ui.render_csf_explorer("/detect", {"category_id": "DE.CM"}, model)
        outcome_page = ui.render_csf_explorer(
            "/detect",
            {"category_id": "DE.CM", "subcategory_id": "DE.CM-09"},
            {
                "csf_subcategory_guidance": {"DE.CM-09": "Watch this PC for unexpected changes."},
                "csf_subcategory_profile_metadata": {
                    "DE.CM-09": {
                        "assessment_method": "evidence",
                        "research_guidance": "Review the local Windows evidence shown here.",
                        "supporting_note_required": False,
                    }
                },
            },
        )
        self.assertIn('/detect?csf_category=DE.CM', category_page)
        self.assertIn('/detect?csf_category=DE.CM&amp;csf_subcategory=DE.CM-09', outcome_page)
        self.assertIn('DE.CM-09', outcome_page)
        self.assertIn('Monitor email, web, file sharing, collaboration services', outcome_page)
        self.assertIn('Monitor software configurations for deviations from security baselines', outcome_page)
        self.assertIn('<ul>', outcome_page)
        self.assertNotIn('Official NIST CSF 2.0 guidance', outcome_page)
        self.assertNotIn('They are guidance, not a Windows-specific checklist', outcome_page)
        self.assertIn('id="csf-evidence-workspace-title" class="kicker">Evidence</div>', outcome_page)
        self.assertIn('Local evidence', outcome_page)
        self.assertIn('Watch this PC for unexpected changes.', outcome_page)
        self.assertIn('No reviewed local-evidence mapping is available yet.', outcome_page)
        self.assertEqual(2, outcome_page.count('class="panel csf-explorer'))
        self.assertIn('csf-explorer-composite', outcome_page)
        self.assertEqual(2, outcome_page.count('tabindex="0"'))
        self.assertLess(outcome_page.index('Categories'), outcome_page.index('Subcategories'))
        self.assertLess(outcome_page.index('Subcategories'), outcome_page.index('id="csf-evidence-workspace-title"'))
        self.assertIn('DE.CM · Continuous Monitoring', category_page)
        self.assertIn('name="task_name" value="Codex IOC Daily Scan"', category_page)
        self.assertIn('name="return_to" value="/detect"', category_page)

    def test_nist_examples_use_plain_text_for_one_and_bullets_for_many(self) -> None:
        one_example = ui.render_nist_implementation_examples({"implementation_examples": ["One official example."]})
        many_examples = ui.render_nist_implementation_examples({"implementation_examples": ["First official example.", "Second official example."]})
        self.assertIn('<p>One official example.</p>', one_example)
        self.assertNotIn('<ul>', one_example)
        self.assertIn('<ul><li>First official example.</li><li>Second official example.</li></ul>', many_examples)

    def test_assessment_method_prototype_changes_its_sections(self) -> None:
        evidence = ui.render_csf_assessment_prototype({"assessment_method": "evidence", "research_guidance": "Evidence guidance."}, "Plain evidence explanation.")
        attestation = ui.render_csf_assessment_prototype({"assessment_method": "attestation", "research_guidance": "Attestation guidance."})
        review = ui.render_csf_assessment_prototype({"assessment_method": "review", "research_guidance": "Review guidance.", "supporting_note_required": True})
        hybrid = ui.render_csf_assessment_prototype({"assessment_method": "hybrid", "research_guidance": "Hybrid guidance.", "supporting_note_required": True})
        self.assertIn('Local evidence', evidence)
        self.assertIn('Plain evidence explanation.', evidence)
        self.assertNotIn('Evidence guidance.', evidence)
        self.assertIn('Confirmation', attestation)
        self.assertNotIn('What to review', review)
        self.assertIn('Supporting basis', review)
        self.assertIn('Human confirmation', hybrid)
