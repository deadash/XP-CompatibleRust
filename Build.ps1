param (
    [string]$action
)

function Set-EnvironmentVariables {
    if ($env:VS_ENV_SET -eq "true") {
        Write-Host "Visual Studio environment variables have already been set."
        return
    }

    Write-Host "Locating Visual Studio installation..."
    $vsWherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $installationPath = & $vsWherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath

    if ($installationPath -and (Test-Path "$installationPath\Common7\Tools\vsdevcmd.bat")) {
        Write-Host "Setting environment variables using VsDevCmd.bat..."
        # Set environment variables using VsDevCmd.bat and export them to JSON format
        $json = & "${env:COMSPEC}" /s /c "`"$installationPath\Common7\Tools\vsdevcmd.bat`" -no_logo -arch=x86 && powershell -Command `"Get-ChildItem env: | Select-Object Name,Value | ConvertTo-Json`""
      
        # Check if the command executed successfully
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to execute $installationPath\Common7\Tools\vsdevcmd.bat with error code: $LASTEXITCODE"
        } else {
            # Convert JSON string back to objects and update the environment variables in the current PowerShell session
            $envVars = $json | ConvertFrom-Json
            foreach ($envVar in $envVars) {
                Set-Item -Path "env:$($envVar.Name)" -Value $envVar.Value
            }
            # Mark environment variables as set
            $env:VS_ENV_SET = "true"
        }
    } else {
        Write-Host "Visual Studio installation or VsDevCmd.bat not found."
    }

    # Set additional environment variables
    $env:PATH = "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Bin;" + $env:PATH
    $env:INCLUDE = "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Include;" + $env:INCLUDE
    $env:LIB = "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib;" + $env:LIB
    $env:CL = "/D_USING_V110_SDK71_"
}

function Build {
    Write-Host "Starting build process..."
    Set-EnvironmentVariables
    Push-Location xpstub
    nmake
    Pop-Location
}

function Clean {
    Write-Host "Starting clean process..."
    Set-EnvironmentVariables
    Push-Location xpstub
    nmake clean
    Pop-Location
}

Switch ($action) {
    "build" {
        Build
    }
    "clean" {
        Clean
    }
    Default {
        Write-Host "Usage: Build.ps1 -action [build|clean]"
        Write-Host "build: Compiles the project."
        Write-Host "clean: Cleans the build artifacts."
    }
}
