# Posh-Nessus
PowerShell v3.0 or above Module for automating Tenable Nessus 6.X Vulnerability Scanner using the REST API introduced in version 6 of the scanner.

** This Module is still in development **

# Install

At the moment there is no installer for the module since it is in development. If you wish to try it out you follow the steps bellow.

First ensure you are running PowerShell 3.0 or preferably 4.0 by looking at the $PSVersionTable variable in a PowerShell session where PSVesion is the version of PowerShell.

```
PS C:\> $PSVersionTable

Name                           Value
----                           -----
PSVersion                      4.0
WSManStackVersion              3.0
SerializationVersion           1.1.0.1
CLRVersion                     4.0.30319.34209
BuildVersion                   6.3.9600.17400
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0}
PSRemotingProtocolVersion      2.2

```

From a PowerShell session running as administrator run:
```
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
```
List of command to install the module that can be copy pasted in to a Powershell session.

```PowerShell
# Make sure the module is not loaded
Remove-Module Posh-Nessus -ErrorAction SilentlyContinue
# Download latest version
$webclient = New-Object System.Net.WebClient
$url = "https://github.com/tenable/Posh-Nessus/archive/master.zip"
Write-Host "Downloading latest version of Posh-Nessus from $url" -ForegroundColor Cyan
$file = "$($env:TEMP)\Posh-Nessus.zip"
$webclient.DownloadFile($url,$file)
Write-Host "File saved to $file" -ForegroundColor Green
# Unblock and Decompress
Unblock-File -Path $file
$targetondisk = "$([System.Environment]::GetFolderPath('MyDocuments'))\WindowsPowerShell\Modules"
New-Item -ItemType Directory -Force -Path $targetondisk | out-null
$shell_app=new-object -com shell.application
$zip_file = $shell_app.namespace($file)
Write-Host "Uncompressing the Zip file to $($targetondisk)" -ForegroundColor Cyan
$destination = $shell_app.namespace($targetondisk)
$destination.Copyhere($zip_file.items(), 0x10)
# Rename and import
Write-Host "Renaming folder" -ForegroundColor Cyan
Rename-Item -Path ($targetondisk+"\Posh-Nessus-master") -NewName "Posh-Nessus" -Force
Write-Host "Module has been installed" -ForegroundColor Green
Import-Module -Name Posh-Nessus
Get-Command -Module Posh-Nessus
``` 