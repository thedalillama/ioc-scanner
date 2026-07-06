Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$uri = 'http://127.0.0.1:8765/'
$outPath = 'C:\CodexTest\ui-verify.png'

$form = New-Object System.Windows.Forms.Form
$form.Width = 1400
$form.Height = 1800
$form.StartPosition = 'Manual'
$form.Left = -32000
$form.Top = -32000

$browser = New-Object System.Windows.Forms.WebBrowser
$browser.ScrollBarsEnabled = $true
$browser.ScriptErrorsSuppressed = $true
$browser.Dock = 'Fill'
$form.Controls.Add($browser)

$done = $false
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1500
$timer.Add_Tick({
    if ($browser.ReadyState -eq 'Complete' -and $browser.Document -ne $null -and $browser.Document.Body -ne $null) {
        $timer.Stop()
        $width = [Math]::Max(1400, $browser.Document.Body.ScrollRectangle.Width + 40)
        $height = [Math]::Max(1800, $browser.Document.Body.ScrollRectangle.Height + 40)
        $browser.Width = $width
        $browser.Height = $height
        $form.Width = $width
        $form.Height = $height
        $bmp = New-Object System.Drawing.Bitmap($width, $height)
        $browser.DrawToBitmap($bmp, (New-Object System.Drawing.Rectangle(0, 0, $width, $height)))
        $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()
        $done = $true
        $form.Close()
    }
})

$browser.Navigate($uri)
$timer.Start()
[void]$form.ShowDialog()
if (-not $done) { throw 'Screenshot capture did not complete.' }
Write-Output $outPath
