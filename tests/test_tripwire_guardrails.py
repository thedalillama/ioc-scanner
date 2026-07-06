import json
import sqlite3
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_HELPER = ROOT / "posture-drift-rules.ps1"
BASELINE_HELPER = ROOT / "tripwire-posture-baseline.ps1"
ACCEPT_HELPER = ROOT / "accept-posture-drift.ps1"


class TripwireGuardrailTests(unittest.TestCase):
    def run_engine(self, rules_payload: dict | None = None, rules_file_text: str | None = None, use_missing_rules_path: bool = False, accepted_payload: dict | None = None, accepted_file_text: str | None = None, use_missing_accepted_path: bool = False, accepted_db_as_directory: bool = False, accepted_db_path_override: Path | None = None) -> dict:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            rules_path = temp_root / "posture-drift-rules.json"
            if rules_payload is not None:
                rules_path.write_text(json.dumps(rules_payload), encoding="utf-8")
            elif rules_file_text is not None:
                rules_path.write_text(rules_file_text, encoding="utf-8")
            elif not use_missing_rules_path:
                rules_path.write_text((ROOT / "profiles" / "posture-drift-rules.json").read_text(encoding="utf-8-sig"), encoding="utf-8")

            if use_missing_rules_path:
                rules_arg = temp_root / "missing-posture-drift-rules.json"
            else:
                rules_arg = rules_path

            if accepted_db_path_override is not None:
                accepted_db_path = accepted_db_path_override
            else:
                accepted_db_path = temp_root / "accepted-posture-drift.db"
            accepted_fallback_path = temp_root / "accepted-posture-drift.json"
            if accepted_payload is not None:
                accepted_fallback_path.write_text(json.dumps(accepted_payload), encoding="utf-8")
            elif accepted_file_text is not None:
                accepted_fallback_path.write_text(accepted_file_text, encoding="utf-8")
            elif accepted_db_as_directory:
                accepted_db_path.mkdir()
            elif use_missing_accepted_path:
                accepted_db_path = temp_root / "missing-accepted-posture-drift.db"

            script = textwrap.dedent(
                rf"""
                . '{BASELINE_HELPER}'
                . '{RULES_HELPER}'

                function New-TestChange {{
                    param(
                        [string]$Category,
                        [string]$Name,
                        [string]$ChangeType,
                        [string]$Path,
                        [string]$OldValue,
                        [string]$NewValue,
                        [string]$Notes = '',
                        [string]$Severity = 'Review',
                        [string]$Classification = 'review',
                        [string]$Interpretation = '',
                        [string]$CsfMapping = ''
                    )
                    [pscustomobject]@{{
                        Category = $Category
                        Name = $Name
                        ChangeType = $ChangeType
                        Path = $Path
                        OldValue = $OldValue
                        NewValue = $NewValue
                        Notes = $Notes
                        Severity = $Severity
                        Classification = $Classification
                        Interpretation = $Interpretation
                        CsfMapping = $CsfMapping
                        GuardrailMatched = $false
                        GuardrailReason = ''
                        MatchedRuleId = ''
                        MatchedRuleDescription = ''
                        RecommendedAction = ''
                    }}
                }}

                $snapshot = [pscustomobject]@{{
                    ScheduledTasks = @(
                        [pscustomobject]@{{
                            Name = '\GoogleUserPEH'
                            Author = 'Google LLC'
                            Actions = '"C:\Program Files\Google\Chrome\Application\chrome.exe" --system-level'
                        }},
                        [pscustomobject]@{{
                            Name = '\ZoomUpdateTaskUser-S-1-5-21-1234'
                            Author = 'Zoom Video Communications, Inc.'
                            Actions = '"C:\Users\me\AppData\Roaming\Zoom\bin\Zoom.exe" --silent'
                        }}
                    )
                }}

                $changes = @(
                    (New-TestChange -Category 'SecurityControl' -Name 'Microsoft Defender exclusions' -ChangeType 'Modified' -Path 'DefenderExclusions' -OldValue 'C:\Safe' -NewValue 'C:\Safe|C:\Temp\Bad' -Notes 'Added exclusions: C:\Temp\Bad'),
                    (New-TestChange -Category 'SecurityControl' -Name 'Windows Firewall profiles' -ChangeType 'Modified' -Path 'FirewallProfiles' -OldValue 'Domain=On|Private=On|Public=On' -NewValue 'Domain=Off|Private=On|Public=On'),
                    (New-TestChange -Category 'SecurityControl' -Name 'Local administrators' -ChangeType 'Modified' -Path 'LocalAdministrators' -OldValue 'BUILTIN\Administrators|me' -NewValue 'BUILTIN\Administrators|me|evil' -Notes 'Added local administrators: evil'),
                    (New-TestChange -Category 'AppIntegrity' -Name 'invoke-host-tripwire.ps1' -ChangeType 'Modified' -Path 'C:\CodexTest\invoke-host-tripwire.ps1' -OldValue 'True|AAA|1|2026-01-01T00:00:00Z' -NewValue 'True|BBB|2|2026-01-02T00:00:00Z'),
                    (New-TestChange -Category 'AppIntegrity' -Name 'profiles\posture-drift-rules.json' -ChangeType 'Modified' -Path 'C:\CodexTest\profiles\posture-drift-rules.json' -OldValue 'Sha256=OLDHASH' -NewValue 'Sha256=NEWHASH'),
                    (New-TestChange -Category 'ScheduledTask' -Name '\BadTempTask' -ChangeType 'Modified' -Path '\BadTempTask' -OldValue '"C:\Program Files\Vendor\vendor.exe"' -NewValue '"C:\Users\me\AppData\Local\Temp\evil.exe"'),
                    (New-TestChange -Category 'ScheduledTask' -Name '\EncodedPowerShellTask' -ChangeType 'Modified' -Path '\EncodedPowerShellTask' -OldValue 'powershell.exe -File C:\CodexTest\safe.ps1' -NewValue 'powershell.exe -EncodedCommand QUJDRA=='),
                    (New-TestChange -Category 'WatchedFile' -Name 'RunPlatformExperienceHelper_Metrics' -ChangeType 'Modified' -Path 'C:\Windows\System32\Tasks\GoogleUserPEH' -OldValue 'old' -NewValue 'new'),
                    (New-TestChange -Category 'WatchedFile' -Name 'ZoomUpdateTaskUser-S-1-5-21-1234' -ChangeType 'Modified' -Path 'C:\Windows\System32\Tasks\ZoomUpdateTaskUser-S-1-5-21-1234' -OldValue 'old' -NewValue 'new'),
                    (New-TestChange -Category 'Service' -Name 'AarSvc_1234' -ChangeType 'Modified' -Path 'ImagePath' -OldValue 'C:\Windows\System32\svchost.exe -k AarSvcGroup' -NewValue 'C:\Windows\System32\svchost.exe -k AarSvcGroup')
                )

                $result = Invoke-TripwirePostureRuleEngine -Changes $changes -Snapshot $snapshot -RulesPath '{rules_arg}' -AcceptedDriftPath '{accepted_db_path}' -AcceptedDriftJsonFallbackPath '{accepted_fallback_path}'
                $summary = Get-TripwirePostureSummary -Snapshot $snapshot -Changes $result.Changes -RuleEngineResult $result
                [pscustomobject]@{{
                    engine = [pscustomobject]@{{
                        RulesFileStatus = $result.RulesFileStatus
                        RulesLoadedCount = $result.RulesLoadedCount
                        RuleMatchesCount = $result.RuleMatchesCount
                        Warning = $result.Warning
                        AcceptedDriftStatus = $result.AcceptedDriftStatus
                        AcceptedDriftLoadedCount = $result.AcceptedDriftLoadedCount
                        AcceptedDriftMatchCount = $result.AcceptedDriftMatchCount
                    }}
                    summary = $summary
                    changes = @($result.Changes)
                }} | ConvertTo-Json -Depth 8
                """
            )
            script_path = temp_root / "tripwire_rule_engine_test.ps1"
            script_path.write_text(script, encoding="utf-8")
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script_path),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
        return json.loads(result.stdout)

    def create_report_file(self, temp_root: Path, report: dict, filename: str = "tripwire-report.json") -> Path:
        report_path = temp_root / filename
        report_path.write_text(json.dumps(report), encoding="utf-8")
        return report_path

    def run_accept_helper(self, report_path: Path, state_db_path: Path, finding_index: int | None = None, finding_id: str | None = None, reason: str | None = None, accepted_by: str | None = "Technician", expires_utc: str | None = None) -> subprocess.CompletedProcess[str]:
        args = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ACCEPT_HELPER),
            "-ReportPath",
            str(report_path),
            "-StateDbPath",
            str(state_db_path),
        ]
        if finding_index is not None:
            args.extend(["-FindingIndex", str(finding_index)])
        if finding_id is not None:
            args.extend(["-FindingId", finding_id])
        if reason is not None:
            args.extend(["-Reason", reason])
        if accepted_by is not None:
            args.extend(["-AcceptedBy", accepted_by])
        if expires_utc is not None:
            args.extend(["-ExpiresUtc", expires_utc])
        return subprocess.run(args, cwd=ROOT, capture_output=True, text=True)

    def read_accepted_rows(self, db_path: Path) -> list[sqlite3.Row]:
        if not db_path.exists():
            return []
        with sqlite3.connect(db_path) as connection:
            connection.row_factory = sqlite3.Row
            try:
                return list(connection.execute("SELECT * FROM accepted_posture_drift ORDER BY acceptance_id"))
            except sqlite3.OperationalError:
                return []

    def test_rule_engine_with_default_catalog(self) -> None:
        payload = self.run_engine()
        records = payload["changes"]
        by_name = {record["Name"]: record for record in records}
        engine = payload["engine"]
        summary = payload["summary"]

        self.assertEqual(engine["RulesFileStatus"], "external")
        self.assertGreaterEqual(engine["RulesLoadedCount"], 30)
        self.assertGreaterEqual(engine["RuleMatchesCount"], 9)
        self.assertEqual(summary["observed_posture_change_count"], 10)
        self.assertEqual(summary["expected_operational_change_count"], 3)
        self.assertEqual(summary["accepted_posture_change_count"], 0)
        self.assertEqual(summary["posture_review_count"], 0)
        self.assertEqual(summary["response_required_count"], 7)
        self.assertEqual(summary["guardrail_protected_count"], 7)

        self.assertTrue(by_name["Microsoft Defender exclusions"]["GuardrailMatched"])
        self.assertEqual(by_name["Microsoft Defender exclusions"]["Classification"], "warning")
        self.assertEqual(by_name["Microsoft Defender exclusions"]["MatchedRuleId"], "guardrail-defender-exclusion-added")

        self.assertTrue(by_name["Windows Firewall profiles"]["GuardrailMatched"])
        self.assertEqual(by_name["Windows Firewall profiles"]["MatchedRuleId"], "guardrail-firewall-disabled")

        self.assertTrue(by_name["Local administrators"]["GuardrailMatched"])
        self.assertEqual(by_name["Local administrators"]["MatchedRuleId"], "guardrail-local-admin-added")

        self.assertTrue(by_name["invoke-host-tripwire.ps1"]["GuardrailMatched"])
        self.assertIn("guardrail-app", by_name["invoke-host-tripwire.ps1"]["MatchedRuleId"])

        self.assertTrue(by_name["\BadTempTask"]["GuardrailMatched"])
        self.assertEqual(by_name["\BadTempTask"]["Classification"], "critical")
        self.assertEqual(by_name["\BadTempTask"]["MatchedRuleId"], "guardrail-scheduled-task-suspicious")

        self.assertTrue(by_name["\EncodedPowerShellTask"]["GuardrailMatched"])
        self.assertEqual(by_name["\EncodedPowerShellTask"]["Classification"], "critical")

        self.assertFalse(by_name["RunPlatformExperienceHelper_Metrics"]["GuardrailMatched"])
        self.assertEqual(by_name["RunPlatformExperienceHelper_Metrics"]["Classification"], "expected")
        self.assertEqual(by_name["RunPlatformExperienceHelper_Metrics"]["MatchedRuleId"], "churn-googleuserpeh-expected")

        self.assertFalse(by_name["ZoomUpdateTaskUser-S-1-5-21-1234"]["GuardrailMatched"])
        self.assertEqual(by_name["ZoomUpdateTaskUser-S-1-5-21-1234"]["Classification"], "expected")
        self.assertEqual(by_name["ZoomUpdateTaskUser-S-1-5-21-1234"]["MatchedRuleId"], "churn-zoom-updater-expected")

        self.assertFalse(by_name["AarSvc_1234"]["GuardrailMatched"])
        self.assertEqual(by_name["AarSvc_1234"]["Classification"], "expected")
        self.assertEqual(by_name["AarSvc_1234"]["MatchedRuleId"], "churn-per-user-service-expected")

    def test_missing_rule_file_falls_back_safely(self) -> None:
        payload = self.run_engine(use_missing_rules_path=True)
        self.assertEqual(payload["engine"]["RulesFileStatus"], "missing_builtin_fallback")
        self.assertIn("Built-in defaults were used", payload["engine"]["Warning"])
        by_name = {record["Name"]: record for record in payload["changes"]}
        self.assertEqual(by_name["RunPlatformExperienceHelper_Metrics"]["Classification"], "expected")
        self.assertEqual(by_name["Microsoft Defender exclusions"]["Classification"], "warning")

    def test_invalid_rule_file_falls_back_safely(self) -> None:
        payload = self.run_engine(rules_file_text="{ not valid json }")
        self.assertEqual(payload["engine"]["RulesFileStatus"], "invalid_builtin_fallback")
        self.assertIn("Built-in defaults were used", payload["engine"]["Warning"])

    def test_disabled_rule_is_ignored(self) -> None:
        rules_payload = json.loads((ROOT / "profiles" / "posture-drift-rules.json").read_text(encoding="utf-8-sig"))
        for rule in rules_payload["rules"]:
            if rule["rule_id"] == "churn-googleuserpeh-expected":
                rule["enabled"] = False
        payload = self.run_engine(rules_payload=rules_payload)
        by_name = {record["Name"]: record for record in payload["changes"]}
        self.assertNotEqual(by_name["RunPlatformExperienceHelper_Metrics"]["MatchedRuleId"], "churn-googleuserpeh-expected")
        self.assertEqual(by_name["RunPlatformExperienceHelper_Metrics"]["Classification"], "review")

    def test_guardrail_rule_runs_before_churn_rule(self) -> None:
        rules_payload = {
            "schema_version": 1,
            "rules": [
                {
                    "rule_id": "churn-scheduled-task-test",
                    "enabled": True,
                    "priority": 10,
                    "description": "Test churn rule.",
                    "rule_type": "churn",
                    "section_pattern": "RuntimeDrift",
                    "item_type_pattern": "ScheduledTask",
                    "item_name_pattern": "\BadTempTask",
                    "classification": "expected",
                    "severity": "Info",
                    "csf_mapping": "DE.CM",
                    "interpretation": "Should not win.",
                    "recommended_action": "No action"
                },
                {
                    "rule_id": "guardrail-scheduled-task-test",
                    "enabled": True,
                    "priority": 999,
                    "description": "Test guardrail rule.",
                    "rule_type": "guardrail",
                    "section_pattern": "RuntimeDrift",
                    "item_type_pattern": "ScheduledTask",
                    "item_name_pattern": "\BadTempTask",
                    "condition_id": "suspicious_persistence_command",
                    "classification": "critical",
                    "severity": "Critical",
                    "csf_mapping": "DE.CM / DE.AE",
                    "interpretation": "Guardrail should win.",
                    "recommended_action": "Review",
                    "guardrail_reason": "Test guardrail"
                }
            ]
        }
        payload = self.run_engine(rules_payload=rules_payload)
        by_name = {record["Name"]: record for record in payload["changes"]}
        self.assertEqual(by_name["\BadTempTask"]["MatchedRuleId"], "guardrail-scheduled-task-test")
        self.assertTrue(by_name["\BadTempTask"]["GuardrailMatched"])
        self.assertEqual(by_name["\BadTempTask"]["Classification"], "critical")


    def test_missing_accepted_drift_file_falls_back_safely(self) -> None:
        payload = self.run_engine(use_missing_accepted_path=True)
        self.assertEqual(payload["engine"]["AcceptedDriftStatus"], "sqlite_missing_created")
        self.assertEqual(payload["engine"]["AcceptedDriftLoadedCount"], 0)
        self.assertEqual(payload["engine"]["AcceptedDriftMatchCount"], 0)
        by_name = {record["Name"]: record for record in payload["changes"]}
        self.assertFalse(by_name["invoke-host-tripwire.ps1"].get("IsAcceptedDrift", False))

    def test_accepted_app_json_drift_becomes_accepted(self) -> None:
        accepted_payload = {
            "schema_version": 1,
            "entries": [
                {
                    "AcceptanceId": "ACC-20260630-000001-test",
                    "Enabled": True,
                    "Scope": "exact",
                    "Section": "AppIntegrityBaseline",
                    "ItemName": "profiles\posture-drift-rules.json",
                    "ItemType": "AppIntegrity",
                    "Field": "CurrentValue",
                    "AcceptedCurrentValue": "Sha256=NEWHASH",
                    "BaselineValue": "Sha256=OLDHASH",
                    "MatchedRuleId": "guardrail-app-json-changed",
                    "Reason": "Reviewed app rule catalog update",
                    "AcceptedBy": "Technician",
                    "AcceptedUtc": "2026-06-30T00:00:00Z",
                    "ExpiresUtc": None,
                    "SourceReportId": "TEST",
                    "CsfMapping": "GV.OV, DE.CM"
                }
            ]
        }
        payload = self.run_engine(accepted_payload=accepted_payload)
        by_name = {record["Name"]: record for record in payload["changes"]}
        json_change = by_name["profiles\posture-drift-rules.json"]
        self.assertTrue(json_change.get("IsAcceptedDrift"))
        self.assertEqual(json_change["Classification"], "accepted")
        self.assertEqual(json_change["Severity"], "Info")
        self.assertEqual(json_change["AcceptanceId"], "ACC-20260630-000001-test")
        self.assertEqual(payload["engine"]["AcceptedDriftMatchCount"], 1)
        self.assertEqual(payload["engine"]["AcceptedDriftLoadedCount"], 1)
        self.assertEqual(payload["engine"]["AcceptedDriftStatus"], "sqlite_imported_json")

    def test_accepted_app_script_drift_becomes_accepted(self) -> None:
        accepted_payload = {
            "schema_version": 1,
            "entries": [
                {
                    "AcceptanceId": "ACC-20260630-000002-test",
                    "Enabled": True,
                    "Scope": "exact",
                    "Section": "AppIntegrityBaseline",
                    "ItemName": "invoke-host-tripwire.ps1",
                    "ItemType": "AppIntegrity",
                    "Field": "CurrentValue",
                    "AcceptedCurrentValue": "True|BBB|2|2026-01-02T00:00:00Z",
                    "BaselineValue": "True|AAA|1|2026-01-01T00:00:00Z",
                    "MatchedRuleId": "guardrail-app-script-changed",
                    "Reason": "Reviewed app collector update",
                    "AcceptedBy": "Technician",
                    "AcceptedUtc": "2026-06-30T00:00:00Z",
                    "ExpiresUtc": None,
                    "SourceReportId": "TEST",
                    "CsfMapping": "GV.OV, DE.CM"
                }
            ]
        }
        payload = self.run_engine(accepted_payload=accepted_payload)
        by_name = {record["Name"]: record for record in payload["changes"]}
        script_change = by_name["invoke-host-tripwire.ps1"]
        self.assertTrue(script_change.get("IsAcceptedDrift"))
        self.assertEqual(script_change["Classification"], "accepted")
        self.assertEqual(script_change["Severity"], "Info")
        self.assertEqual(payload["engine"]["AcceptedDriftStatus"], "sqlite_imported_json")

    def test_json_fallback_is_used_when_sqlite_fails(self) -> None:
        accepted_payload = {
            "schema_version": 1,
            "entries": [
                {
                    "AcceptanceId": "ACC-FALLBACK",
                    "Enabled": True,
                    "Scope": "exact",
                    "Section": "AppIntegrityBaseline",
                    "ItemName": "invoke-host-tripwire.ps1",
                    "ItemType": "AppIntegrity",
                    "Field": "CurrentValue",
                    "AcceptedCurrentValue": "True|BBB|2|2026-01-02T00:00:00Z",
                    "Reason": "JSON fallback test",
                    "AcceptedUtc": "2026-06-30T00:00:00Z",
                    "SourceReportId": "TEST"
                }
            ]
        }
        payload = self.run_engine(accepted_payload=accepted_payload, accepted_db_as_directory=True)
        by_name = {record["Name"]: record for record in payload["changes"]}
        script_change = by_name["invoke-host-tripwire.ps1"]
        self.assertTrue(script_change.get("IsAcceptedDrift"))
        self.assertEqual(script_change["Classification"], "accepted")
        self.assertEqual(script_change["Severity"], "Info")
        self.assertIn(payload["engine"]["AcceptedDriftStatus"], ("json_fallback", "sqlite_imported_json"))

    def test_expired_acceptance_is_ignored(self) -> None:
        accepted_payload = {
            "schema_version": 1,
            "entries": [
                {
                    "AcceptanceId": "ACC-EXPIRED",
                    "Enabled": True,
                    "Scope": "exact",
                    "Section": "AppIntegrityBaseline",
                    "ItemName": "invoke-host-tripwire.ps1",
                    "ItemType": "AppIntegrity",
                    "Field": "CurrentValue",
                    "AcceptedCurrentValue": "True|BBB|2|2026-01-02T00:00:00Z",
                    "Reason": "Expired acceptance",
                    "AcceptedUtc": "2026-06-01T00:00:00Z",
                    "ExpiresUtc": "2026-06-01T00:00:00Z",
                    "SourceReportId": "TEST"
                }
            ]
        }
        payload = self.run_engine(accepted_payload=accepted_payload)
        by_name = {record["Name"]: record for record in payload["changes"]}
        self.assertFalse(by_name["invoke-host-tripwire.ps1"].get("IsAcceptedDrift", False))
        self.assertNotEqual(by_name["invoke-host-tripwire.ps1"].get("Classification"), "accepted")

    def test_mismatched_current_value_is_ignored(self) -> None:
        accepted_payload = {
            "schema_version": 1,
            "entries": [
                {
                    "AcceptanceId": "ACC-MISMATCH",
                    "Enabled": True,
                    "Scope": "exact",
                    "Section": "AppIntegrityBaseline",
                    "ItemName": "invoke-host-tripwire.ps1",
                    "ItemType": "AppIntegrity",
                    "Field": "CurrentValue",
                    "AcceptedCurrentValue": "DIFFERENT",
                    "Reason": "Wrong current value",
                    "AcceptedUtc": "2026-06-30T00:00:00Z",
                    "SourceReportId": "TEST"
                }
            ]
        }
        payload = self.run_engine(accepted_payload=accepted_payload)
        by_name = {record["Name"]: record for record in payload["changes"]}
        self.assertFalse(by_name["invoke-host-tripwire.ps1"].get("IsAcceptedDrift", False))
        self.assertNotEqual(by_name["invoke-host-tripwire.ps1"].get("Classification"), "accepted")

    def test_dangerous_findings_are_not_suppressed_by_acceptance(self) -> None:
        accepted_payload = {
            "schema_version": 1,
            "entries": [
                {
                    "AcceptanceId": "ACC-DANGER",
                    "Enabled": True,
                    "Scope": "exact",
                    "Section": "SecurityControlBaseline",
                    "ItemName": "Microsoft Defender exclusions",
                    "ItemType": "SecurityControl",
                    "Field": "CurrentValue",
                    "AcceptedCurrentValue": "C:\\Safe|C:\\Temp\\Bad",
                    "Reason": "Should not suppress a guardrail",
                    "AcceptedUtc": "2026-06-30T00:00:00Z",
                    "SourceReportId": "TEST"
                },
                {
                    "AcceptanceId": "ACC-TEMP",
                    "Enabled": True,
                    "Scope": "exact",
                    "Section": "RuntimeDrift",
                    "ItemName": "\BadTempTask",
                    "ItemType": "ScheduledTask",
                    "Field": "CurrentValue",
                    "AcceptedCurrentValue": "C:\\Users\\me\\AppData\\Local\\Temp\\evil.exe",
                    "Reason": "Should not suppress persistence",
                    "AcceptedUtc": "2026-06-30T00:00:00Z",
                    "SourceReportId": "TEST"
                }
            ]
        }
        payload = self.run_engine(accepted_payload=accepted_payload)
        by_name = {record["Name"]: record for record in payload["changes"]}
        defender = by_name["Microsoft Defender exclusions"]
        temp_task = by_name["\BadTempTask"]
        encoded = by_name["\EncodedPowerShellTask"]
        self.assertNotEqual(defender.get("Severity"), "Info")
        self.assertNotEqual(defender.get("Classification"), "accepted")
        self.assertTrue(defender.get("GuardrailMatched"))
        self.assertNotEqual(temp_task.get("Severity"), "Info")
        self.assertNotEqual(temp_task.get("Classification"), "accepted")
        self.assertTrue(temp_task.get("GuardrailMatched"))
        self.assertEqual(encoded.get("Severity"), "Critical")
        self.assertNotEqual(encoded.get("Classification"), "accepted")

    def test_helper_creates_sqlite_acceptance_row_for_app_integrity_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            state_db = temp_root / "state" / "ioc-store.db"
            report = {
                "ReportId": "TEST-APP-INTEGRITY",
                "Changes": [
                    {
                        "Section": "AppIntegrityBaseline",
                        "ItemName": "profiles\posture-drift-rules.json",
                        "Field": "CurrentValue",
                        "CurrentValue": "SHA256=NEWHASH",
                        "BaselineValue": "SHA256=OLDHASH",
                        "MatchedRuleId": "guardrail-app-json-changed",
                        "MatchedRuleDescription": "App JSON changed",
                        "Classification": "warning",
                        "Severity": "Warning",
                        "CsfMapping": "GV.OV, DE.CM"
                    }
                ]
            }
            report_path = self.create_report_file(temp_root, report)

            helper = self.run_accept_helper(report_path, state_db, finding_index=1, reason="Reviewed app rule catalog update")
            self.assertEqual(helper.returncode, 0, helper.stdout + helper.stderr)
            self.assertIn("AcceptanceId:", helper.stdout)

            rows = self.read_accepted_rows(state_db)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["scope"], "exact")
            self.assertEqual(row["section"], "AppIntegrityBaseline")
            self.assertEqual(row["item_name"], "profiles\posture-drift-rules.json")
            self.assertEqual(row["accepted_current_value"], "SHA256=NEWHASH")
            self.assertEqual(row["reason"], "Reviewed app rule catalog update")
            self.assertEqual(row["enabled"], 1)

            payload = self.run_engine(accepted_db_path_override=state_db)
            by_name = {record["Name"]: record for record in payload["changes"]}
            accepted = by_name["profiles\posture-drift-rules.json"]
            self.assertTrue(accepted.get("IsAcceptedDrift"))
            self.assertEqual(accepted["Classification"], "accepted")
            self.assertEqual(accepted["Severity"], "Info")
            self.assertGreaterEqual(payload["engine"]["AcceptedDriftLoadedCount"], 1)
            self.assertGreaterEqual(payload["engine"]["AcceptedDriftMatchCount"], 1)

    def test_helper_refuses_dangerous_defender_and_firewall_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            state_db = temp_root / "state" / "ioc-store.db"
            defender_report = {
                "ReportId": "TEST-DANGER-DEFENDER",
                "Changes": [
                    {
                        "Section": "SecurityControlBaseline",
                        "ItemName": "Microsoft Defender exclusions",
                        "ItemType": "SecurityControl",
                        "Field": "CurrentValue",
                        "CurrentValue": "C:\Safe|C:\Temp\Bad",
                        "MatchedRuleId": "guardrail-defender-exclusion-added",
                        "Classification": "warning",
                        "Severity": "Warning"
                    }
                ]
            }
            firewall_report = {
                "ReportId": "TEST-DANGER-FIREWALL",
                "Changes": [
                    {
                        "Section": "SecurityControlBaseline",
                        "ItemName": "Windows Firewall profiles",
                        "ItemType": "SecurityControl",
                        "Field": "CurrentValue",
                        "CurrentValue": "Domain=Off|Private=On|Public=On",
                        "MatchedRuleId": "guardrail-firewall-disabled",
                        "Classification": "warning",
                        "Severity": "Warning"
                    }
                ]
            }
            defender_path = self.create_report_file(temp_root, defender_report, "defender.json")
            firewall_path = self.create_report_file(temp_root, firewall_report, "firewall.json")

            defender_result = self.run_accept_helper(defender_path, state_db, finding_index=1, reason="Should refuse")
            firewall_result = self.run_accept_helper(firewall_path, state_db, finding_index=1, reason="Should refuse")

            self.assertNotEqual(defender_result.returncode, 0)
            self.assertNotEqual(firewall_result.returncode, 0)
            self.assertIn("Refusing to create accepted drift", defender_result.stdout + defender_result.stderr)
            self.assertIn("Refusing to create accepted drift", firewall_result.stdout + firewall_result.stderr)
            self.assertEqual(self.read_accepted_rows(state_db), [])

    def test_helper_requires_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            state_db = temp_root / "state" / "ioc-store.db"
            report = {
                "ReportId": "TEST-REASON",
                "Changes": [
                    {
                        "Section": "AppIntegrityBaseline",
                        "ItemName": "invoke-host-tripwire.ps1",
                        "Field": "CurrentValue",
                        "CurrentValue": "True|BBB|2|2026-01-02T00:00:00Z",
                        "MatchedRuleId": "guardrail-app-script-changed",
                        "Classification": "warning",
                        "Severity": "Warning"
                    }
                ]
            }
            report_path = self.create_report_file(temp_root, report)
            result = self.run_accept_helper(report_path, state_db, finding_index=1, reason=None)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Reason is required", result.stderr + result.stdout)
            self.assertEqual(self.read_accepted_rows(state_db), [])

    def test_helper_does_not_create_wildcard_or_pattern_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            state_db = temp_root / "state" / "ioc-store.db"
            report = {
                "ReportId": "TEST-WILDCARD",
                "Changes": [
                    {
                        "FindingId": "app-json-1",
                        "Section": "AppIntegrityBaseline",
                        "ItemName": "profiles\posture-drift-rules.json",
                        "Field": "CurrentValue",
                        "CurrentValue": "SHA256=NEWHASH",
                        "MatchedRuleId": "guardrail-app-json-changed",
                        "Classification": "warning",
                        "Severity": "Warning"
                    }
                ]
            }
            report_path = self.create_report_file(temp_root, report)
            result = self.run_accept_helper(report_path, state_db, finding_id="app-*")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Specify -FindingIndex or -FindingId to create an acceptance.", result.stdout + result.stderr)
            self.assertEqual(self.read_accepted_rows(state_db), [])

    def test_existing_churn_still_works(self) -> None:
        payload = self.run_engine()
        by_name = {record["Name"]: record for record in payload["changes"]}
        self.assertEqual(by_name["RunPlatformExperienceHelper_Metrics"]["Classification"], "expected")
        self.assertEqual(by_name["ZoomUpdateTaskUser-S-1-5-21-1234"]["Classification"], "expected")
        self.assertEqual(by_name["AarSvc_1234"]["Classification"], "expected")


if __name__ == "__main__":
    unittest.main()
