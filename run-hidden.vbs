If WScript.Arguments.Count = 0 Then
    WScript.Quit 1
End If

Dim command
command = "cmd.exe /d /s /c " & Chr(34) & WScript.Arguments(0) & Chr(34)

Dim exitCode
exitCode = CreateObject("WScript.Shell").Run(command, 0, True)
WScript.Quit exitCode
