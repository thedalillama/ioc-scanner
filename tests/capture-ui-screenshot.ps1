Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$uri = 'http://127.0.0.1:8765/'
$outPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'ui-verify.png')

$form = New-Object System.Windows.Forms.Form
$form.Width = 1400
$form.Height = 980
$form.StartPosition = 'CenterScreen'

$browser = New-Object System.Windows.Forms.WebBrowser
$browser.Dock = 'Fill'
$browser.ScriptErrorsSuppressed = $true
$form.Controls.Add($browser)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 4000
$timer.Add_Tick({
    $timer.Stop()
    $bitmap = New-Object System.Drawing.Bitmap $form.Width, $form.Height
    $form.DrawToBitmap($bitmap, (New-Object System.Drawing.Rectangle 0,0,$form.Width,$form.Height))
    $bitmap.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bitmap.Dispose()
    $form.Close()
})

$browser.Navigate($uri)
$timer.Start()
[void]$form.ShowDialog()
Write-Host "Saved $outPath"
