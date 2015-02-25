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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
            $Params.Add('alt_targets', $AlternateTarget -join ' ')
        }

        foreach($Connection in $ToProcess)
        {
            $Scans =  InvokeNessusRestRequest -SessionObject $Connection -Path "/scans/$($ScanId)/launch" -Method 'Post' -Parameter $Params

            if ($Scans -is [psobject])
            {

                $ScanProps = [ordered]@{}
                $ScanProps.add('ScanUUID', $scans.scan_uuid)
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
                    $ScanProps.add('CreationDate', $origin.AddSeconds($scan.creation_date).ToLocalTime())
                    $ScanProps.add('LastModified', $origin.AddSeconds($scan.last_modification_date).ToLocalTime())
                    $ScanProps.add('StartTime', $origin.AddSeconds($scan.starttime).ToLocalTime())
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
                $ScanDetails
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
    [OutputType([int])]
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
        $Encrypted
    )

    Begin
    {
        if($Encrypted)
        {
            $ContentType = 'application/octet-stream'
            $URIPath = '/file/upload?no_enc=1'
        }
        else
        {
            $ContentType = 'text/plain'
            $URIPath = '/file/upload'
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
            $req = [System.Net.WebRequest]::Create("$($Connection.uri)$($URIPath)")
            $req.Method = 'POST'
            $req.AllowWriteStreamBuffering = $true
            $req.SendChunked = $false
            $req.KeepAlive = $true
            

            # Set the proper headers.
            $headers = New-Object -TypeName System.Net.WebHeaderCollection
            $req.Headers = $headers
            # Prep the POST Headers for the message
            $req.Headers.Add('X-Cookie',"token=$($connection.token)")
            $req.Headers.Add('X-Requested-With','XMLHttpRequest')
            $req.Headers.Add('Accept-Language: en-US')
            $req.Headers.Add('Accept-Encoding: gzip,deflate')
            $req.UserAgent = "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko')"
            $boundary = '----------------------------' + [DateTime]::Now.Ticks.ToString('x')
            $req.ContentType = 'multipart/form-data; boundary=' + $boundary
            [byte[]]$boundarybytes = [System.Text.Encoding]::ASCII.GetBytes('--' + $boundary + "`r`n")
            [string]$formdataTemplate = '--' + $boundary 
            [string]$formitem = [string]::Format($formdataTemplate, 'Filename', $fileinfo.name)
            [byte[]]$formitembytes = [System.Text.Encoding]::UTF8.GetBytes($formitem)
            
            # Headder
            [string]$headerTemplate = "Content-Disposition: form-data; name=`"{0}`"; filename=`"{1}`"`r`nContent-Type: $($ContentType)`r`n`r`n"
            [string]$header = [string]::Format($headerTemplate, 'Filedata', (get-item $file).name)
            [byte[]]$headerbytes = [System.Text.Encoding]::UTF8.GetBytes($header)

            # Footer
            [string]$footerTemplate = "`r`n" + $boundary + '--'
            [byte[]]$footerBytes = [System.Text.Encoding]::UTF8.GetBytes($footerTemplate)


            # Read the file and format the message
            $stream = $req.GetRequestStream()
            $rdr = new-object System.IO.FileStream($fileinfo.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
            [byte[]]$buffer = new-object byte[] $rdr.Length
            [int]$total = [int]$count = 0
            $stream.Write($boundarybytes, 0, $boundarybytes.Length)
            $stream.Write($headerbytes, 0,$headerbytes.Length)
            $count = $rdr.Read($buffer, 0, $buffer.Length)
            do{
                $stream.Write($buffer, 0, $count)
                $count = $rdr.Read($buffer, 0, $buffer.Length)
            }while ($count > 0)
            $stream.Write($footerBytes, 0, $footerBytes.Length)
            $stream.close()

            try
            {
                # Upload the file
                $response = $req.GetResponse()

                # Read the response
                $respstream = $response.GetResponseStream()
                $sr = new-object System.IO.StreamReader $respstream
                $result = $sr.ReadToEnd()
                $UploadName = ConvertFrom-Json -InputObject $result
           }
           catch
           {
                throw $_
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