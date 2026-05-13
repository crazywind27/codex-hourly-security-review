Option Explicit

Function Quote(ByVal value)
    Quote = Chr(34) & Replace(value, Chr(34), Chr(34) & Chr(34)) & Chr(34)
End Function

Dim shell, fso, scriptDir, powershell, scriptPath, configPath, command, exitCode

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
powershell = shell.ExpandEnvironmentStrings("%SystemRoot%") & "\System32\WindowsPowerShell\v1.0\powershell.exe"
scriptPath = fso.BuildPath(scriptDir, "Run-HourlySecurityReview.ps1")

If Not fso.FileExists(scriptPath) Then
    WScript.Quit 2
End If

If WScript.Arguments.Count >= 1 Then
    configPath = WScript.Arguments(0)
Else
    configPath = fso.BuildPath(scriptDir, "config.json")
End If

shell.CurrentDirectory = scriptDir
command = Quote(powershell) & " -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -File " & Quote(scriptPath) & " -ConfigPath " & Quote(configPath)
exitCode = shell.Run(command, 0, True)

WScript.Quit exitCode
