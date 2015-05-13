#region Scans
####################################################################

<#
.Synops
   Pause a running scan on a Nessus server.
.DESCRIPTION
   Pause a running scan on a Nessus server.
.EXAMPLE
    Suspend-NessusScan -SessionId 0 -ScanId 46


    Name            : Whole Lab
    ScanId          : 46
    Status          : running
    Enabled         : 
    Owner           : carlos
    AlternateTarget : 
    IsPCI           : 
    UserPermission  : 
    CreationDate    : 2/24/2015 6:17:11 AM
    LastModified    : 2/24/2015 6:17:11 AM
    StartTime       : 12/31/1969 8:00:00 PM

    PS C:\> Get-NessusScan -SessionId 0 -Status Paused


    Name           : Whole Lab
    ScanId         : 46
    Status         : paused
    Enabled        : False
    FolderId       : 2
    Owner          : carlos
    UserPermission : 
    Rules          : 
    Shared         : False
    TimeZone       : 
    CreationDate   : 2/24/2015 6:17:11 AM
    LastModified   : 2/24/2015 6:22:17 AM
    StartTime      : 12/31/1969 8:00:00 PM
#>
function Suspend-NessusScan
{
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$false,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $ScanId 
    )

    Begin
    {
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    }
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }
        
        foreach($Connection in $ToProcess)
        {
            $Scans =  InvokeNessusRestRequest -SessionObject $Connection -Path "/scans/$($ScanId)/pause" -Method 'Post'

            if ($Scans -is [psobject])
            {
                $scan = $Scans.scan
                $ScanProps = [ordered]@{}
                $ScanProps.add('Name', $scan.name)
                $ScanProps.add('ScanId', $ScanId)
                $ScanProps.add('HistoryId', $scan.id)
                $ScanProps.add('Status', $scan.status)
                $ScanProps.add('Enabled', $scan.enabled)
                $ScanProps.add('Owner', $scan.owner)
                $ScanProps.add('AlternateTarget', $scan.ownalt_targetser)
                $ScanProps.add('IsPCI', $scan.is_pci)
                $ScanProps.add('UserPermission', $PermissionsId2Name[$scan.user_permissions])
                $ScanProps.add('CreationDate', $origin.AddSeconds($scan.creation_date).ToLocalTime())
                $ScanProps.add('LastModified', $origin.AddSeconds($scan.last_modification_date).ToLocalTime())
                $ScanProps.add('StartTime', $origin.AddSeconds($scan.starttime).ToLocalTime())
                $ScanProps.Add('SessionId', $Connection.SessionId)
                $ScanObj = New-Object -TypeName psobject -Property $ScanProps
                $ScanObj.pstypenames[0] = 'Nessus.RunningScan'
                $ScanObj
            }
        }
    }
    End{}
}


<#
.Synopsis
   Resume a paused scan on a Nessus server.
.DESCRIPTION
   Resume a paused scan on a Nessus server.
.EXAMPLE
   Resume-NessusScan -SessionId 0 -ScanId 46


    Name            : Whole Lab
    ScanId          : 46
    Status          : paused
    Enabled         : 
    Owner           : carlos
    AlternateTarget : 
    IsPCI           : 
    UserPermission  : 
    CreationDate    : 2/24/2015 6:17:11 AM
    LastModified    : 2/24/2015 6:17:11 AM
    StartTime       : 12/31/1969 8:00:00 PM




    PS C:\> Get-NessusScan -SessionId 0 -Status Running


    Name           : Whole Lab
    ScanId         : 46
    Status         : running
    Enabled        : False
    FolderId       : 2
    Owner          : carlos
    UserPermission : 
    Rules          : 
    Shared         : False
    TimeZone       : 
    CreationDate   : 2/24/2015 6:17:11 AM
    LastModified   : 2/24/2015 6:25:34 AM
    StartTime      : 12/31/1969 8:00:00 PM
#>
function Resume-NessusScan
{
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $ScanId 
    )

    Begin
    {
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    }
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }
        

        foreach($Connection in $ToProcess)
        {
            $Scans =  InvokeNessusRestRequest -SessionObject $Connection -Path "/scans/$($ScanId)/resume" -Method 'Post'

            if ($Scans -is [psobject])
            {
                $scan = $Scans.scan
                $ScanProps = [ordered]@{}
                $ScanProps.add('Name', $scan.name)
                $ScanProps.add('ScanId', $ScanId)
                $ScanProps.add('HistoryId', $scan.id)
                $ScanProps.add('Status', $scan.status)
                $ScanProps.add('Enabled', $scan.enabled)
                $ScanProps.add('Owner', $scan.owner)
                $ScanProps.add('AlternateTarget', $scan.ownalt_targetser)
                $ScanProps.add('IsPCI', $scan.is_pci)
                $ScanProps.add('UserPermission', $PermissionsId2Name[$scan.user_permissions])
                $ScanProps.add('CreationDate', $origin.AddSeconds($scan.creation_date).ToLocalTime())
                $ScanProps.add('LastModified', $origin.AddSeconds($scan.last_modification_date).ToLocalTime())
                $ScanProps.add('StartTime', $origin.AddSeconds($scan.starttime).ToLocalTime())
                $ScanProps.Add('SessionId', $Connection.SessionId)
                $ScanObj = New-Object -TypeName psobject -Property $ScanProps
                $ScanObj.pstypenames[0] = 'Nessus.RunningScan'
                $ScanObj
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Cancel a scan on a Nessus server.
.DESCRIPTION
   Cancel a scan on a Nessus server.
.EXAMPLE
   Stop-NessusScan -SessionId 0 -ScanId 46


    Name            : Whole Lab
    ScanId          : 46
    Status          : running
    Enabled         : 
    Owner           : carlos
    AlternateTarget : 
    IsPCI           : 
    UserPermission  : 
    CreationDate    : 2/24/2015 6:17:11 AM
    LastModified    : 2/24/2015 6:17:11 AM
    StartTime       : 12/31/1969 8:00:00 PM




    PS C:\> Get-NessusScan -SessionId 0 


    Name           : Whole Lab
    ScanId         : 46
    Status         : canceled
    Enabled        : False
    FolderId       : 2
    Owner          : carlos
    UserPermission : 
    Rules          : 
    Shared         : False
    TimeZone       : 
    CreationDate   : 2/24/2015 6:17:11 AM
    LastModified   : 2/24/2015 6:27:20 AM
    StartTime      : 12/31/1969 8:00:00 PM

#>
function Stop-NessusScan
{
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $ScanId 
    )

    Begin
    {
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    }
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }
        

        foreach($Connection in $ToProcess)
        {
            $Scans =  InvokeNessusRestRequest -SessionObject $Connection -Path "/scans/$($ScanId)/stop" -Method 'Post'

            if ($Scans -is [psobject])
            {
                $scan = $Scans.scan
                $ScanProps = [ordered]@{}
                $ScanProps.add('Name', $scan.name)
                $ScanProps.add('ScanId', $ScanId)
                $ScanProps.add('HistoryId', $scan.id)
                $ScanProps.add('Status', $scan.status)
                $ScanProps.add('Enabled', $scan.enabled)
                $ScanProps.add('Owner', $scan.owner)
                $ScanProps.add('AlternateTarget', $scan.ownalt_targetser)
                $ScanProps.add('IsPCI', $scan.is_pci)
                $ScanProps.add('UserPermission', $PermissionsId2Name[$scan.user_permissions])
                $ScanProps.add('CreationDate', $origin.AddSeconds($scan.creation_date).ToLocalTime())
                $ScanProps.add('LastModified', $origin.AddSeconds($scan.last_modification_date).ToLocalTime())
                $ScanProps.add('StartTime', $origin.AddSeconds($scan.starttime).ToLocalTime())
                $ScanProps.Add('SessionId', $Connection.SessionId)
                $ScanObj = New-Object -TypeName psobject -Property $ScanProps
                $ScanObj.pstypenames[0] = 'Nessus.RunningScan'
                $ScanObj
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Launch a scan on a Nessus server.
.DESCRIPTION
   Launch a scan on a Nessus server.
.EXAMPLE
   Start-NessusScan -SessionId 0 -ScanId 15 -AlternateTarget 192.168.11.11,192.168.11.12

    ScanUUID                                                                                                                                                                 
    --------                                                                                                                                                                 
    70aff007-3e61-242f-e90c-ee96ace62ca57ea8eb669c32205a                                                                                                                     



    PS C:\> Get-NessusScan -SessionId 0 -Status Running


    Name           : Lab1
    ScanId         : 15
    Status         : running
    Enabled        : True
    FolderId       : 2
    Owner          : carlos
    UserPermission : Sysadmin
    Rules          : 
    Shared         : False
    TimeZone       : 
    CreationDate   : 2/25/2015 7:39:49 PM
    LastModified   : 2/25/2015 7:40:28 PM
    StartTime      : 12/31/1969 8:00:00 PM
#>
function Start-NessusScan
{
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $ScanId,

        [Parameter(Mandatory=$false,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [string[]]
        $AlternateTarget 
    )

    Begin
    {
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    }
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }
        $Params = @{}

        if($AlternateTarget)
        {
            $Params.Add('alt_targets', $AlternateTarget)
        }
        $paramJson = ConvertTo-Json -InputObject $params -Compress

        foreach($Connection in $ToProcess)
        {
            $Scans =  InvokeNessusRestRequest -SessionObject $Connection -Path "/scans/$($ScanId)/launch" -Method 'Post' -Parameter $paramJson

            if ($Scans -is [psobject])
            {

                $ScanProps = [ordered]@{}
                $ScanProps.add('ScanUUID', $scans.scan_uuid)
                $ScanProps.add('ScanId', $ScanId)
                $ScanProps.add('SessionId', $Connection.SessionId)
                $ScanObj = New-Object -TypeName psobject -Property $ScanProps
                $ScanObj.pstypenames[0] = 'Nessus.LaunchedScan'
                $ScanObj
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Get scans present on a Nessus server.
.DESCRIPTION
   Get scans present on a Nessus server.
.EXAMPLE
    Get-NessusScan -SessionId 0 -Status Completed


    Name           : Lab Domain Controller Audit
    ScanId         : 61
    Status         : completed
    Enabled        : False
    FolderId       : 2
    Owner          : carlos
    UserPermission : Sysadmin
    Rules          : 
    Shared         : False
    TimeZone       : 
    CreationDate   : 2/25/2015 2:45:53 PM
    LastModified   : 2/25/2015 2:46:34 PM
    StartTime      : 12/31/1969 8:00:00 PM

    Name           : Whole Lab
    ScanId         : 46
    Status         : completed
    Enabled        : False
    FolderId       : 2
    Owner          : carlos
    UserPermission : Sysadmin
    Rules          : 
    Shared         : False
    TimeZone       : 
    CreationDate   : 2/24/2015 6:32:45 AM
    LastModified   : 2/24/2015 6:46:20 AM
    StartTime      : 12/31/1969 8:00:00 PM

    Name           : Lab1
    ScanId         : 15
    Status         : completed
    Enabled        : True
    FolderId       : 2
    Owner          : carlos
    UserPermission : Sysadmin
    Rules          : 
    Shared         : False
    TimeZone       : 
    CreationDate   : 2/18/2015 5:40:54 PM
    LastModified   : 2/18/2015 5:41:01 PM
    StartTime      : 12/31/1969 8:00:00 PM

    Name           : Lab2
    ScanId         : 17
    Status         : completed
    Enabled        : False
    FolderId       : 2
    Owner          : carlos
    UserPermission : Sysadmin
    Rules          : 
    Shared         : False
    TimeZone       : 
    CreationDate   : 2/13/2015 9:12:31 PM
    LastModified   : 2/13/2015 9:19:04 PM
    StartTime      : 12/31/1969 8:00:00 PM
#>
function Get-NessusScan
{
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$false,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $FolderId,

        [Parameter(Mandatory=$false,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Completed', 'Imported', 'Running', 'Paused', 'Canceled')]
        [string]
        $Status
    )

    Begin
    {
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    }
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }
        $Params = @{}

        if($FolderId)
        {
            $Params.Add('folder_id', $FolderId)
        }

        foreach($Connection in $ToProcess)
        {
            $Scans =  InvokeNessusRestRequest -SessionObject $Connection -Path '/scans' -Method 'Get' -Parameter $Params

            if ($Scans -is [psobject])
            {
                
                if($Status.length -gt 0)
                {
                    $Scans2Process = $Scans.scans | Where-Object {$_.status -eq $Status.ToLower()}
                }
                else
                {
                    $Scans2Process = $Scans.scans
                }
                foreach ($scan in $Scans2Process)
                {
                    $ScanProps = [ordered]@{}
                    $ScanProps.add('Name', $scan.name)
                    $ScanProps.add('ScanId', $scan.id)
                    $ScanProps.add('Status', $scan.status)
                    $ScanProps.add('Enabled', $scan.enabled)
                    $ScanProps.add('FolderId', $scan.folder_id)
                    $ScanProps.add('Owner', $scan.owner)
                    $ScanProps.add('UserPermission', $PermissionsId2Name[$scan.user_permissions])
                    $ScanProps.add('Rules', $scan.rrules)
                    $ScanProps.add('Shared', $scan.shared)
                    $ScanProps.add('TimeZone', $scan.timezone)
                    $ScanProps.add('Scheduled', $scan.control)
                    $ScanProps.add('DashboardEnabled', $scan.use_dashboard)
                    $ScanProps.Add('SessionId', $Connection.SessionId)                 
                    $ScanProps.add('CreationDate', $origin.AddSeconds($scan.creation_date).ToLocalTime())
                    $ScanProps.add('LastModified', $origin.AddSeconds($scan.last_modification_date).ToLocalTime())

                    if ($scan.starttime -cnotlike "*T*")
                    {
                        $ScanProps.add('StartTime', $origin.AddSeconds($scan.starttime).ToLocalTime())
                    }
                    else
                    {
                        $StartTime = [datetime]::ParseExact($scan.starttime,"yyyyMMddTHHmmss",
                                     [System.Globalization.CultureInfo]::InvariantCulture,
                                     [System.Globalization.DateTimeStyles]::None)
                        $ScanProps.add('StartTime', $StartTime)
                    }
                    $ScanObj = New-Object -TypeName psobject -Property $ScanProps
                    $ScanObj.pstypenames[0] = 'Nessus.Scan'
                    $ScanObj
                }
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Export-NessusScan
{
    [CmdletBinding()]
    Param
    (
       # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $ScanId,

        [Parameter(Mandatory=$true,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Nessus', 'HTML', 'PDF', 'CSV', 'DB')]
        [string]
        $Format,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [String]
        $OutFile,

        [Parameter(Mandatory=$false,
                   Position=3,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Vuln_Hosts_Summary', 'Vuln_By_Host', 
                     'Compliance_Exec', 'Remediations', 
                     'Vuln_By_Plugin', 'Compliance')]
        [string[]]
        $Chapters,

        [Parameter(Mandatory=$false,
                   Position=4,
                   ValueFromPipelineByPropertyName=$true)]
        [Int32]
        $HistoryID,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true)]
        [securestring]
        $Password

    )

    Begin
    {
    }
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }

        $ExportParams = @{}

        if($Format -eq 'DB' -and $Password)
        {
            $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $Password
            $ExportParams.Add('password', $Credentials.GetNetworkCredential().Password)
        }

        if($Format)
        {
            $ExportParams.Add('format', $Format.ToLower())
        }

        foreach($Connection in $ToProcess)
        {
            $path =  "/scans/$($ScanId)/export"
            Write-Verbose -Message "Exporting scan with Id of $($ScanId) in $($Format) format."
            $FileID = InvokeNessusRestRequest -SessionObject $Connections -Path $path  -Method 'Post' -Parameter $ExportParams
            if ($FileID -is [psobject])
            {
                $FileStatus = ''
                while ($FileStatus.status -ne 'ready')
                {
                    try
                    {
                        $FileStatus = InvokeNessusRestRequest -SessionObject $Connections -Path "/scans/$($ScanId)/export/$($FileID.file)/status"  -Method 'Get'
                        Write-Verbose -Message "Status of export is $($FileStatus.status)"
                    }
                    catch
                    {
                        break
                    }
                    Start-Sleep -Seconds 1
                }
                if ($FileStatus.status -eq 'ready')
                {
                    Write-Verbose -Message "Downloading report to $($OutFile)"
                    InvokeNessusRestRequest -SessionObject $Connections -Path "/scans/$($ScanId)/export/$($FileID.file)/download" -Method 'Get' -OutFile $OutFile
                }
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Show-NessusScanDetail
{
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $ScanId,

        [Parameter(Mandatory=$false,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [Int32]
        $HistoryId 
    )

    Begin
    {
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    }
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }
        $Params = @{}

        if($HistoryId)
        {
            $Params.Add('history_id', $HistoryId)
        }

        foreach($Connection in $ToProcess)
        {
            $ScanDetails =  InvokeNessusRestRequest -SessionObject $Connection -Path "/scans/$($ScanId)" -Method 'Get' -Parameter $Params

            if ($ScanDetails -is [psobject])
            {
                
                $ScanDetailProps = [ordered]@{}
                $hosts = @()
                $history = @()

                # Process Scan Info
                $ScanInfo = [ordered]@{}
                $ScanInfo.add('Name', $ScanDetails.info.name)
                $ScanInfo.add('ScanId', $ScanDetails.info.object_id)
                $ScanInfo.add('Status', $ScanDetails.info.status)
                $ScanInfo.add('UUID', $ScanDetails.info.uuid)
                $ScanInfo.add('Policy', $ScanDetails.info.policy)
                $ScanInfo.add('FolderId', $ScanDetails.info.folder_id)
                $ScanInfo.add('ScannerName', $ScanDetails.info.scanner_name)
                $ScanInfo.add('HostCount', $ScanDetails.info.hostcount)
                $ScanInfo.add('Targets', $ScanDetails.info.targets)
                $ScanInfo.add('AlternetTargetsUsed', $ScanDetails.info.alt_targets_used)
                $ScanInfo.add('HasAuditTrail', $ScanDetails.info.hasaudittrail)
                $ScanInfo.add('HasKb', $ScanDetails.info.haskb)
                $ScanInfo.add('ACL', $ScanDetails.info.acls)
                $ScanInfo.add('Permission', $PermissionsId2Name[$ScanDetails.info.user_permissions])
                $ScanInfo.add('EditAllowed', $ScanDetails.info.edit_allowed)
                $ScanInfo.add('LastModified', $origin.AddSeconds($ScanDetails.info.timestamp).ToLocalTime())
                $ScanInfo.add('ScanStart', $origin.AddSeconds($ScanDetails.info.scan_start).ToLocalTime())
                $ScanInfo.Add('SessionId', $Connection.SessionId)
                $InfoObj = New-Object -TypeName psobject -Property $ScanInfo
                $InfoObj.pstypenames[0] = 'Nessus.Scan.Info'


                # Process host info.
                foreach ($Host in $ScanDetails.hosts)
                {
                    $HostProps = [ordered]@{}
                    $HostProps.Add('HostName', $Host.hostname)
                    $HostProps.Add('HostId', $Host.host_id)
                    $HostProps.Add('Critical', $Host.critical)
                    $HostProps.Add('High',  $Host.high)
                    $HostProps.Add('Medium', $Host.medium)
                    $HostProps.Add('Low', $Host.low)
                    $HostProps.Add('Info', $Host.info)
                    $HostObj = New-Object -TypeName psobject -Property $HostProps
                    $HostObj.pstypenames[0] = 'Nessus.Scan.Host'
                    $hosts += $HostObj
                } 

                # Process hostory info.
                foreach ($History in $ScanDetails.history)
                {
                    $HistoryProps = [ordered]@{}
                    $HistoryProps['HistoryId'] = $History.history_id
                    $HistoryProps['UUID'] = $History.uuid
                    $HistoryProps['Status'] = $History.status
                    $HistoryProps['Type'] = $History.type
                    $HistoryProps['CreationDate'] = $origin.AddSeconds($History.creation_date).ToLocalTime()
                    $HistoryProps['LastModifiedDate'] = $origin.AddSeconds($History.last_modification_date).ToLocalTime()
                    $HistObj = New-Object -TypeName psobject -Property $HistoryProps
                    $HistObj.pstypenames[0] = 'Nessus.Scan.History'
                    $history += $HistObj
                }

                $ScanDetails
            }
        }
    }
    End{}
}


<#
.Synopsis
   Show details of a speific host on a scan in a Nessus server.
.DESCRIPTION
   Long description
.EXAMPLE
   Show-NessusScanHostDetail -SessionId 0 -ScanId 46 -HostId 31 | fl


    Info            : @{host_start=Tue Feb 24 06:32:45 2015; host-fqdn=fw1.darkoperator.com; 
                       host_end=Tue Feb 24 06:35:52 2015; operating-system=FreeBSD 8.3-RELEASE-p16 
                      (i386); host-ip=192.168.1.1}
    Vulnerabilities : {@{count=1; hostname=192.168.1.1; plugin_name=Nessus Scan Information; vuln_index=0; 
                      severity=0; plugin_id=19506; severity_index=0; plugin_family=Settings; host_id=31}, 
                      @{count=3; hostname=192.168.1.1; plugin_name=Nessus SYN scanner; vuln_index=1; severity=0; 
                      plugin_id=11219; 
                      severity_index=1; plugin_family=Port scanners; host_id=31}, @{count=1;
                      hostname=192.168.1.1; plugin_name=Unsupported Unix Operating System; 
                      vuln_index=2; severity=4; plugin_id=33850; severity_index=2; 
                      plugin_family=General; host_id=31}}
    Compliance      : {}
#>
function Show-NessusScanHostDetail
{
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $ScanId,

        [Parameter(Mandatory=$true,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $HostId,

        [Parameter(Mandatory=$false,
                   Position=3,
                   ValueFromPipelineByPropertyName=$true)]
        [Int32]
        $HistoryId 
    )

    Begin{}
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }
        $Params = @{}

        if($HistoryId)
        {
            $Params.Add('history_id', $HistoryId)
        }

        foreach($Connection in $ToProcess)
        {
            $ScanDetails =  InvokeNessusRestRequest -SessionObject $Connection -Path "/scans/$($ScanId)/hosts/$($HostId)" -Method 'Get' -Parameter $Params

            if ($ScanDetails -is [psobject])
            {                
                $HostProps = [ordered]@{}
                $HostProps.Add('Info', $ScanDetails.info)
                $HostProps.Add('Vulnerabilities', $ScanDetails.vulnerabilities)
                $HostProps.Add('Compliance', $ScanDetails.compliance)
                $HostProps.Add('ScanId', $ScanId)
                $HostProps.Add('SessionId', $Connection.SessionId)
                $HostObj = New-Object -TypeName psobject -Property $HostProps
                $HostObj.pstypenames[0] = 'Nessus.Scan.HostDetails'
                $HostObj             
            }
        }
    }
    End{}
}


<#
.Synopsis
   Show the hosts present in a specific scan on a Nessus server.
.DESCRIPTION
   Show the hosts present in a specific scan on a Nessus server. The number
   of vulnerabilities found per severity.
.EXAMPLE
   Show-NessusScanHost -SessionId 0 -ScanId 46


    HostName : 192.168.1.253
    HostId   : 252
    Critical : 0
    High     : 1
    Medium   : 0
    Low      : 0
    Info     : 3

    HostName : 192.168.1.250
    HostId   : 251
    Critical : 0
    High     : 2
    Medium   : 0
    Low      : 0
    Info     : 3

    HostName : 192.168.1.242
    HostId   : 244
    Critical : 0
    High     : 0
    Medium   : 1
    Low      : 0
    Info     : 40

    HostName : 192.168.1.223
    HostId   : 225
    Critical : 0
    High     : 0
    Medium   : 0
    Low      : 0
    Info     : 6

    HostName : 192.168.1.218
    HostId   : 219
    Critical : 0
    High     : 0
    Medium   : 0
    Low      : 0
    Info     : 2

    HostName : 192.168.1.217
    HostId   : 221
    Critical : 0
    High     : 0
    Medium   : 0
    Low      : 0
    Info     : 4
#>
function Show-NessusScanHost
{
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $ScanId,

        [Parameter(Mandatory=$false,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [Int32]
        $HistoryId 
    )

    Begin{}
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }
        $Params = @{}

        if($HistoryId)
        {
            $Params.Add('history_id', $HistoryId)
        }

        foreach($Connection in $ToProcess)
        {
            $ScanDetails =  InvokeNessusRestRequest -SessionObject $Connection -Path "/scans/$($ScanId)" -Method 'Get' -Parameter $Params

            if ($ScanDetails -is [psobject])
            {
                foreach ($Host in $ScanDetails.hosts)
                {
                    $HostProps = [ordered]@{}
                    $HostProps.Add('HostName', $Host.hostname)
                    $HostProps.Add('HostId', $Host.host_id)
                    $HostProps.Add('Critical', $Host.critical)
                    $HostProps.Add('High',  $Host.high)
                    $HostProps.Add('Medium', $Host.medium)
                    $HostProps.Add('Low', $Host.low)
                    $HostProps.Add('Info', $Host.info)
                    $HostProps.Add('ScanId', $ScanId)
                    $HostProps.Add('SessionId', $Connection.SessionId)
                    $HostObj = New-Object -TypeName psobject -Property $HostProps
                    $HostObj.pstypenames[0] = 'Nessus.Scan.Host'
                    $HostObj
                } 
            }
        }
    }
    End{}
}


<#
.Synopsis
   Shows the history of times ran for a specific scan in a Nessus server.
.DESCRIPTION
   Shows the history of times ran for a specific scan in a Nessus server.
.EXAMPLE
   Show-NessusScanHistory -SessionId 0 -ScanId 46


    HistoryId        : 47
    UUID             : 909d61c2-5f6d-605d-6e4d-79739bbe1477dd85043154a6077f
    Status           : completed
    Type             : local
    CreationDate     : 2/24/2015 2:52:35 AM
    LastModifiedDate : 2/24/2015 5:57:33 AM

    HistoryId        : 48
    UUID             : e8df16c4-390c-b4d8-0ae5-ea7c48867bd57618d7bd96b32122
    Status           : canceled
    Type             : local
    CreationDate     : 2/24/2015 6:17:11 AM
    LastModifiedDate : 2/24/2015 6:27:20 AM

    HistoryId        : 49
    UUID             : e933c0be-3b16-5a44-be32-b17e32f2a2e6f7be26c34082817a
    Status           : canceled
    Type             : local
    CreationDate     : 2/24/2015 6:31:52 AM
    LastModifiedDate : 2/24/2015 6:32:43 AM

    HistoryId        : 50
    UUID             : 484d03b9-3196-4cc7-6567-4e99d8cc0e949924ccfb6ce4af3d
    Status           : completed
    Type             : local
    CreationDate     : 2/24/2015 6:32:45 AM
    LastModifiedDate : 2/24/2015 6:46:20 AM
#>
function Show-NessusScanHistory
{
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $ScanId
    )

    Begin
    {
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    }
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }
        $Params = @{}

        if($HistoryId)
        {
            $Params.Add('history_id', $HistoryId)
        }

        foreach($Connection in $ToProcess)
        {
            $ScanDetails =  InvokeNessusRestRequest -SessionObject $Connection -Path "/scans/$($ScanId)" -Method 'Get' -Parameter $Params

            if ($ScanDetails -is [psobject])
            {
                foreach ($History in $ScanDetails.history)
                {
                    $HistoryProps = [ordered]@{}
                    $HistoryProps['HistoryId'] = $History.history_id
                    $HistoryProps['UUID'] = $History.uuid
                    $HistoryProps['Status'] = $History.status
                    $HistoryProps['Type'] = $History.type
                    $HistoryProps['CreationDate'] = $origin.AddSeconds($History.creation_date).ToLocalTime()
                    $HistoryProps['LastModifiedDate'] = $origin.AddSeconds($History.last_modification_date).ToLocalTime()
                    $HistoryProps['SessionId'] = $Connection.SessionId
                    $HistObj = New-Object -TypeName psobject -Property $HistoryProps
                    $HistObj.pstypenames[0] = 'Nessus.Scan.History'
                    $HistObj
                } 
            }
        }
    }
    End{}
}


<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function New-NessusScan
{
    [CmdletBinding(DefaultParameterSetName='Policy')]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true,
                   Position=2,
                   ParameterSetName = 'Tempplate',
                   ValueFromPipelineByPropertyName=$true)]
        [string]
        $PolicyUUID,

        [Parameter(Mandatory=$true,
                   Position=2,
                   ParameterSetName = 'Policy',
                   ValueFromPipelineByPropertyName=$true)]
        [int]
        $PolicyId,

        [Parameter(Mandatory=$true,
                   Position=3,
                   ValueFromPipelineByPropertyName=$true)]
        [string[]]
        $Target,

        [Parameter(Mandatory=$true,
                   Position=4,
                   ValueFromPipelineByPropertyName=$true)]
        [bool]
        $Enabled,

        [Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true)]
        [string]
        $Description,

        [Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true)]
        [Int]
        $FolderId,

        [Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true)]
        [Int]
        $ScannerId,

        [Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true)]
        [string[]]
        $Email,

        [Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true)]
        [switch]
        $CreateDashboard
    )

    Begin
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }

        

        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0

    }
    Process
    {
        foreach($Connection in $ToProcess)
        {
            # Join emails as a single comma separated string.
            $emails = $email -join ","

            # Join targets as a single comma separated string.
            $Targets = $target -join ","

            # Build Scan JSON
            $settings = @{
                'name' = $Name
                'text_targets' = $Targets
            }

            if ($FolderId) {$settings.Add('folder_id',$FolderId)}
            if ($ScannerId) {$settings.Add('scanner_id', $ScannerId)}
            if ($Email.Length -gt 0) {$settings.Add('emails', $emails)}
            if ($Description.Length -gt 0) {$settings.Add('description', $Description)}
            if ($CreateDashboard) {$settings.Add('use_dashboard',$true)}

            switch($PSCmdlet.ParameterSetName)
            {
                'Tempplate'{
                    $scanhash = [ordered]@{ 
                        'uuid' = $PolicyUUID
                        'settings' = $settings
                    }
                }

                'Policy'{
                    $polUUID = $null
                    $Policies = Get-NessusPolicy -SessionId $Connection.SessionId 
                    foreach($Policy in $Policies)
                    {
                        if ($Policy.PolicyId -eq $PolicyId)
                        {
                            $polUUID = $Policy.PolicyUUID
                        }
                    }

                    if ($polUUID -eq $null)
                    {
                        Write-Error -message 'Policy specified does not exist in session.'
                        return
                    }
                    else
                    {
                        $scanhash = [ordered]@{ 
                            'uuid' = $polUUID
                            'settings' = $settings
                        }                      
                    }
                }
            }

            $ScanJson = ConvertTo-Json -InputObject $scanhash -Compress

            $ServerTypeParams = @{
                'SessionObject' = $Connection
                'Path' = '/scans'
                'Method' = 'POST'
                'ContentType' = 'application/json'
                'Parameter' = $ScanJson
            }

            $NewScan =  InvokeNessusRestRequest @ServerTypeParams
            
            foreach ($scan in $NewScan.scan)
            {
                $ScanProps = [ordered]@{}
                $ScanProps.add('Name', $scan.name)
                $ScanProps.add('ScanId', $scan.id)
                $ScanProps.add('Status', $scan.status)
                $ScanProps.add('Enabled', $scan.enabled)
                $ScanProps.add('FolderId', $scan.folder_id)
                $ScanProps.add('Owner', $scan.owner)
                $ScanProps.add('UserPermission', $PermissionsId2Name[$scan.user_permissions])
                $ScanProps.add('Rules', $scan.rrules)
                $ScanProps.add('Shared', $scan.shared)
                $ScanProps.add('TimeZone', $scan.timezone)
                $ScanProps.add('CreationDate', $origin.AddSeconds($scan.creation_date).ToLocalTime())
                $ScanProps.add('LastModified', $origin.AddSeconds($scan.last_modification_date).ToLocalTime())
                $ScanProps.add('StartTime', $origin.AddSeconds($scan.starttime).ToLocalTime())
                $ScanProps.add('Scheduled', $scan.control)
                $ScanProps.add('DashboardEnabled', $scan.use_dashboard)
                $ScanProps.Add('SessionId', $Connection.SessionId)
                    
                $ScanObj = New-Object -TypeName psobject -Property $ScanProps
                $ScanObj.pstypenames[0] = 'Nessus.Scan'
                $ScanObj
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Deletes a scan result from a Nessus server.
.DESCRIPTION
   Deletes a scan result from a Nessus server.
.EXAMPLE
    Get-NessusScan -SessionId 0 -Status Imported | Remove-NessusScan -SessionId 0 -Verbose
    VERBOSE: Removing scan with Id 45
    VERBOSE: DELETE https://192.168.1.211:8834/scans/45 with 0-byte payload
    VERBOSE: received 4-byte response of content type application/json
    VERBOSE: Scan Removed
    VERBOSE: Removing scan with Id 41
    VERBOSE: DELETE https://192.168.1.211:8834/scans/41 with 0-byte payload
    VERBOSE: received 4-byte response of content type application/json
    VERBOSE: Scan Removed
    VERBOSE: Removing scan with Id 39
    VERBOSE: DELETE https://192.168.1.211:8834/scans/39 with 0-byte payload
    VERBOSE: received 4-byte response of content type application/json
    VERBOSE: Scan Removed
    VERBOSE: Removing scan with Id 37
    VERBOSE: DELETE https://192.168.1.211:8834/scans/37 with 0-byte payload
    VERBOSE: received 4-byte response of content type application/json
    VERBOSE: Scan Removed
    VERBOSE: Removing scan with Id 7
    VERBOSE: DELETE https://192.168.1.211:8834/scans/7 with 0-byte payload
    VERBOSE: received 4-byte response of content type application/json
    VERBOSE: Scan Removed
    VERBOSE: Removing scan with Id 5
    VERBOSE: DELETE https://192.168.1.211:8834/scans/5 with 0-byte payload
    VERBOSE: received 4-byte response of content type application/json
    VERBOSE: Scan Removed
#>
function Remove-NessusScan
{
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $ScanId
    )

    Begin{}
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }

        foreach($Connection in $ToProcess)
        {
            Write-Verbose -Message "Removing scan with Id $($ScanId)"
            
            $ScanDetails =  InvokeNessusRestRequest -SessionObject $Connection -Path "/scans/$($ScanId)" -Method 'Delete' -Parameter $Params
            if ($ScanDetails -eq 'null')
            {
                Write-Verbose -Message 'Scan Removed'
            }
            
            
        }
    }
    End{}
}


<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Import-NessusScan
{
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({Test-Path -Path $_})]
        [string]
        $File,

        [Parameter(Mandatory=$false,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [switch]
        $Encrypted,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true)]
        [securestring]
        $Password
    )

    Begin
    {
        if($Encrypted)
        {
            $ContentType = 'application/octet-stream'
            $URIPath = 'file/upload?no_enc=1'
        }
        else
        {
            $ContentType = 'application/octet-stream'
            $URIPath = 'file/upload'
        }

        $netAssembly = [Reflection.Assembly]::GetAssembly([System.Net.Configuration.SettingsSection])

        if($netAssembly)
        {
            $bindingFlags = [Reflection.BindingFlags] "Static,GetProperty,NonPublic"
            $settingsType = $netAssembly.GetType("System.Net.Configuration.SettingsSectionInternal")

            $instance = $settingsType.InvokeMember("Section", $bindingFlags, $null, $null, @())

            if($instance)
            {
                $bindingFlags = "NonPublic","Instance"
                $useUnsafeHeaderParsingField = $settingsType.GetField("useUnsafeHeaderParsing", $bindingFlags)

                if($useUnsafeHeaderParsingField)
                {
                  $useUnsafeHeaderParsingField.SetValue($instance, $true)
                }
            }
        }
    }
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }

        foreach($Connection in $ToProcess)
        {
            $fileinfo = Get-ItemProperty -Path $File
            $FilePath = $fileinfo.FullName
            $RestClient = New-Object RestSharp.RestClient
            $RestRequest = New-Object RestSharp.RestRequest
            $RestClient.UserAgent = 'Posh-SSH'
            $RestClient.BaseUrl = $Connection.uri
            $RestRequest.Method = [RestSharp.Method]::POST
            $RestRequest.Resource = $URIPath
            
            [void]$RestRequest.AddFile('Filedata',$FilePath, 'application/octet-stream')
            [void]$RestRequest.AddHeader('X-Cookie', "token=$($Connection.Token)")
            $result = $RestClient.Execute($RestRequest)
            if ($result.ErrorMessage.Length -gt 0)
            {
                Write-Error -Message $result.ErrorMessage
            }
            else
            {
                $RestParams = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
                $RestParams.add('file', "$($fileinfo.name)")
                if ($Encrypted)
                {
                    $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $Password
                    $RestParams.Add('password', $Credentials.GetNetworkCredential().Password)
                }

                $impParams = @{ 'Body' = $RestParams }
                Invoke-RestMethod -Method Post -Uri "$($Connection.URI)/scans/import" -header @{'X-Cookie' = "token=$($Connection.Token)"} -Body (ConvertTo-Json @{'file' = $fileinfo.name;} -Compress) -ContentType 'application/json'
            }
        }
    }
    End{}
}


<#
.Synopsis
   Get all scan templates available on a Nessus server.
.DESCRIPTION
   Get all scan templates available on a Nessus server.
.EXAMPLE
   Get-NessusScanTemplate -SessionId 0
#>
function Get-NessusScanTemplate
{
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @()

    )

    Begin
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }
    }
    Process
    {
        

        foreach($Connection in $ToProcess)
        {
            $Templates =  InvokeNessusRestRequest -SessionObject $Connection -Path '/editor/scan/templates' -Method 'Get'

            if ($Templates -is [psobject])
            {
                foreach($Template in $Templates.templates)
                {
                    $TmplProps = [ordered]@{}
                    $TmplProps.add('Name', $Template.name)
                    $TmplProps.add('Title', $Template.title)
                    $TmplProps.add('Description', $Template.desc)
                    $TmplProps.add('UUID', $Template.uuid)
                    $TmplProps.add('CloudOnly', $Template.cloud_only)
                    $TmplProps.add('SubscriptionOnly', $Template.subscription_only)
                    $TmplProps.add('SessionId', $Connection.SessionId)
                    $Tmplobj = New-Object -TypeName psobject -Property $TmplProps
                    $Tmplobj.pstypenames[0] = 'Nessus.ScanTemplate'
                    $Tmplobj
                }
            }
        }
    }
    End
    {
    }
}


#endregion