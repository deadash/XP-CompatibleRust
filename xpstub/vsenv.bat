@echo off
setlocal enabledelayedexpansion

set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist %VSWHERE% (
    for /f "usebackq tokens=*" %%i in (`%VSWHERE% -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set InstallDir=%%i
        echo Found Visual Studio installation at: !InstallDir!
    )

    if exist "!InstallDir!\Common7\Tools\VsDevCmd.bat" (
        "!InstallDir!\Common7\Tools\VsDevCmd.bat" %*
    ) else (
        echo VsDevCmd.bat not found.
    )
) else (
    echo vswhere.exe not found. Please refer to https://github.com/microsoft/vswhere for more information.
)