import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class TripwireBaselineRefreshContractTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (ROOT / name).read_text(encoding="utf-8")

    def test_only_the_fixed_refresh_task_can_be_excluded_from_a_baseline(self) -> None:
        source = self.read("invoke-host-tripwire.ps1")
        self.assertIn('[switch]$ExcludeTransientBaselineRefreshTask', source)
        self.assertIn("$transientRefreshTaskName = '\\Codex Tripwire Baseline Refresh'", source)
        self.assertIn('if ($ExcludeTransientBaselineRefreshTask -and $fullTaskName -eq $transientRefreshTaskName)', source)
        self.assertIn('ExcludeTransientBaselineRefreshTask is valid only for Tripwire Baseline mode.', source)
        self.assertIn('ExcludedTransientScheduledTask = if ($ExcludeTransientBaselineRefreshTask)', source)

    def test_system_refresh_runner_is_one_shot_and_refuses_reuse(self) -> None:
        source = self.read("refresh-tripwire-baseline.ps1")
        self.assertIn('$refreshTaskName = "Codex Tripwire Baseline Refresh"', source)
        self.assertIn('New-ScheduledTaskPrincipal -UserId "SYSTEM"', source)
        self.assertIn('-ExcludeTransientBaselineRefreshTask', source)
        self.assertIn('Refusing to reuse existing task $refreshTaskPath', source)
        self.assertIn('Unregister-ScheduledTask -TaskName $refreshTaskName -Confirm:$false', source)
        self.assertIn('The task was retained for investigation.', source)

    def test_installer_and_transfer_media_include_the_refresh_runner(self) -> None:
        self.assertIn('Target = "refresh-tripwire-baseline.ps1"', self.read("install-codex-monitor.ps1"))
        self.assertIn("'refresh-tripwire-baseline.ps1'", self.read("tests/build-transfer-iso.ps1"))


if __name__ == "__main__":
    unittest.main()
