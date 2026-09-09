param(
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$IsoPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'vm-transfer\codex-install.iso')
)
$ErrorActionPreference = 'Stop'
$stageRoot = Join-Path (Split-Path $IsoPath -Parent) 'iso-stage'
if (Test-Path $stageRoot) { [System.IO.Directory]::Delete($stageRoot, $true) }
[System.IO.Directory]::CreateDirectory($stageRoot) | Out-Null
$files = @(
    'README.md',
    'install-codex-monitor.ps1',
    'vm-install.cmd',
    'invoke-host-ioc.ps1',
    'invoke-host-tripwire.ps1',
    'monitor-threat-rss.ps1',
    'start-codex-alert-helper.ps1',
    'import-threat-feeds.ps1',
    'get-codex-monitor-status.ps1',
    'ioc_store.py',
    'run-hidden.vbs',
    'accept-posture-drift.ps1',
    'posture-drift-rules.ps1',
    'tripwire-posture-baseline.ps1',
    'protection-profiles.json',
    'host-tripwire-config.json',
    'ioc-monitor-locations.json',
    'codex-monitor.settings.example.json'
)
$aliases = @{
    'install-codex-monitor.ps1' = 'installer.ps1'
    'invoke-host-ioc.ps1' = 'ioc.ps1'
    'invoke-host-tripwire.ps1' = 'tripwire.ps1'
    'monitor-threat-rss.ps1' = 'rss.ps1'
    'start-codex-alert-helper.ps1' = 'alert-helper.ps1'
    'import-threat-feeds.ps1' = 'feed-import.ps1'
    'get-codex-monitor-status.ps1' = 'status.ps1'
    'ioc_store.py' = 'store.py'
    'run-hidden.vbs' = 'hidden.vbs'
    'host-tripwire-config.json' = 'tripwire-config.json'
    'ioc-monitor-locations.json' = 'ioc-locations.json'
}
$dirs = @('docs','examples','tests','profiles')
foreach ($file in $files) {
    $src = Join-Path $SourceRoot $file
    if (Test-Path $src) {
        $dst = Join-Path $stageRoot $file
        $dstDir = Split-Path $dst -Parent
        if (-not (Test-Path $dstDir)) { [System.IO.Directory]::CreateDirectory($dstDir) | Out-Null }
        [System.IO.File]::Copy($src, $dst, $true)
        if ($aliases.ContainsKey($file)) {
            $aliasDst = Join-Path $stageRoot $aliases[$file]
            [System.IO.File]::Copy($src, $aliasDst, $true)
        }
    }
}
foreach ($dir in $dirs) {
    $srcDir = Join-Path $SourceRoot $dir
    if (Test-Path $srcDir) {
        Copy-Item -LiteralPath $srcDir -Destination $stageRoot -Recurse -Force
    }
}
if (Test-Path $IsoPath) { [System.IO.File]::Delete($IsoPath) }
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class ComStreamCopy
{
    public static void CopyToFile(object comStreamObject, string path)
    {
        var stream = (IStream)comStreamObject;
        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write))
        {
            byte[] buffer = new byte[32768];
            IntPtr readPtr = Marshal.AllocHGlobal(sizeof(int));
            try
            {
                while (true)
                {
                    Marshal.WriteInt32(readPtr, 0);
                    stream.Read(buffer, buffer.Length, readPtr);
                    int read = Marshal.ReadInt32(readPtr);
                    if (read <= 0)
                        break;
                    file.Write(buffer, 0, read);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(readPtr);
            }
        }
    }
}
"@
$fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$fsi.FileSystemsToCreate = 3
$fsi.VolumeName = 'CODEXINSTALL'
$fsi.Root.AddTree($stageRoot, $false)
$result = $fsi.CreateResultImage()
[ComStreamCopy]::CopyToFile($result.ImageStream, $IsoPath)
Write-Output $IsoPath
