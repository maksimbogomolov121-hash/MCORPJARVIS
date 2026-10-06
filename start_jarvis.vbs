Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

batFile = fso.BuildPath(fso.GetParentFolderName(WScript.ScriptFullName), "start_jarvis.bat")

shell.Run """" & batFile & """", 0, False

Set fso = Nothing
Set shell = Nothing