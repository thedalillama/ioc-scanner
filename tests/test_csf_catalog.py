import unittest

import csf_catalog
from csf_guidance import PLAIN_ENGLISH_GUIDANCE_EN_US
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
            {"csf_subcategory_guidance": {"DE.CM-09": "Watch this PC for unexpected changes."}},
        )
        self.assertIn('/detect?csf_category=DE.CM', category_page)
        self.assertIn('/detect?csf_category=DE.CM&amp;csf_subcategory=DE.CM-09', outcome_page)
        self.assertIn('DE.CM-09', outcome_page)
        self.assertIn('Monitor email, web, file sharing, collaboration services', outcome_page)
        self.assertIn('Monitor software configurations for deviations from security baselines', outcome_page)
        self.assertIn('<ul>', outcome_page)
        self.assertNotIn('Watch this PC for unexpected changes.', outcome_page)
        self.assertNotIn('Official NIST CSF 2.0 guidance', outcome_page)
        self.assertNotIn('They are guidance, not a Windows-specific checklist', outcome_page)
        self.assertIn('No Codex Monitor mapping is implemented for this outcome yet.', outcome_page)
        self.assertEqual(4, outcome_page.count('class="panel csf-explorer'))
        self.assertEqual(2, outcome_page.count('tabindex="0"'))
        self.assertLess(outcome_page.index('Categories'), outcome_page.index('Subcategories'))
        self.assertLess(outcome_page.index('Subcategories'), outcome_page.index('>Evidence and actions<'))
        self.assertIn('DE.CM · Continuous Monitoring', category_page)
        self.assertIn('name="task_name" value="Codex IOC Daily Scan"', category_page)
        self.assertIn('name="return_to" value="/detect"', category_page)

    def test_nist_examples_use_plain_text_for_one_and_bullets_for_many(self) -> None:
        one_example = ui.render_nist_implementation_examples({"implementation_examples": ["One official example."]})
        many_examples = ui.render_nist_implementation_examples({"implementation_examples": ["First official example.", "Second official example."]})
        self.assertIn('<p>One official example.</p>', one_example)
        self.assertNotIn('<ul>', one_example)
        self.assertIn('<ul><li>First official example.</li><li>Second official example.</li></ul>', many_examples)
