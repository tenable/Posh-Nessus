# Posh-Nessus
PowerShell v3.0 (or above) module for automating Tenable Nessus 6.x vulnerability scans using the REST API introduced in version 6 of the scanner.

** This Module is still in development **

# Install

At the moment there is no installer for the module since it is in development. If you wish to try it out you can follow the steps bellow.

First ensure you are running PowerShell 3.0 or preferably 4.0 by looking at the `$PSVersionTable` variable in a PowerShell session where `PSVesion` is the version of PowerShell.

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
List of commands to install the module that can be copy pasted in to a Powershell session:

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
# Unblock and decompress
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

## Basic Usage
The module works by creating sessions to one or more Nessus 6 scanners and then using the Session ID of that session to run other cmdlets. To stablish a session the `New-NessusSession` cmdlet is used.

```
PS C:\> New-NessusSession -ComputerName 192.168.1.211 -Credentials (Get-Credential)

cmdlet Get-Credential at command pipeline position 1
Supply values for the following parameters:
Credential


SessionId : 0
URI       : https://192.168.1.211:8834
Token     : 54ffb9f7447079978b6c584ba02c44720f029e468d8a3850

```

Once a session is created the Session ID is given to the other cmdlets/functions to perform the desired task:
```
PS C:\> Get-NessusServerStatus -SessionId 0


Progress :
Status   : ready



PS C:\> Get-NessusSessionInfo -SessionId 0


Id         : 2
Name       : carlos
UserName   : carlos
Email      :
Type       : local
Permission : Sysadmin
LastLogin  : 5/20/2015 9:16:30 PM
Groups     :
Connectors :

```
