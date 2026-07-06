If WScript.Arguments.Count = 0 Then
    WScript.Quit 1
End If

Dim command
command = WScript.Arguments(0)

Dim exitCode
exitCode = CreateObject("WScript.Shell").Run(command, 0, True)
WScript.Quit exitCode
