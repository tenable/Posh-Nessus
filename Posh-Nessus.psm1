if (!(Test-Path variable:Global:NessusConn ))
{
    $Global:NessusConn = New-Object System.Collections.ArrayList
}
 
 $PermissionsId2Name = @{
    16 = 'Read-Only'
    32 = 'Regular'
    64 = 'Administrator'
    128 = 'Sysadmin'
 }

  $PermissionsName2Id = @{
    'Read-Only' = 16
    'Regular' = 32
    'Administrator' = 64
    'Sysadmin' = 128
 }

#region Session

<#
.Synopsis
   Create a new Nessus Session.
.DESCRIPTION
   Creates a new Nessus Session.
.EXAMPLE
   New-NessusSession -ComputerName 192.168.1.205 -Credentials (Get-Credential carlos) -Verbose
   VERBOSE: POST https://192.168.1.205:8834/session with -1-byte payload
   VERBOSE: received 60-byte response of content type application/json


    Id    : 0
    URI   : https://192.168.1.205:8834
    Token : 50168808199c1a2197d180fa62fb9cc3cb9108054911476a
#>
function New-NessusSession
{
    [CmdletBinding()]
    Param
    (
        # Nessus Server IP Address or FQDN to connect to.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string[]]$ComputerName,

        # Port number of the Nessus web service. Default 8834
        [int]
        $Port = 8834,


        # Credentials for connecting to the Nessus Server
        [Parameter(Mandatory=$true,
        Position=1)]
        [Management.Automation.PSCredential]$Credentials
    )

    Begin
    {
        
    }
    Process
    {
        if ([System.Net.ServicePointManager]::CertificatePolicy.ToString() -ne 'IgnoreCerts')
        {
            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('IgnoreCerts')
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('IgnoreCerts', $false)
            $TypeBuilder = $ModuleBuilder.DefineType('IgnoreCerts', 'AutoLayout, AnsiClass, Class, Public, BeforeFieldInit', [System.Object], [System.Net.ICertificatePolicy])
            $TypeBuilder.DefineDefaultConstructor('PrivateScope, Public, HideBySig, SpecialName, RTSpecialName') | Out-Null
            $MethodInfo = [System.Net.ICertificatePolicy].GetMethod('CheckValidationResult')
            $MethodBuilder = $TypeBuilder.DefineMethod($MethodInfo.Name, 'PrivateScope, Public, Virtual, HideBySig, VtableLayoutMask', $MethodInfo.CallingConvention, $MethodInfo.ReturnType, ([Type[]] ($MethodInfo.GetParameters() | % {$_.ParameterType})))
            $ILGen = $MethodBuilder.GetILGenerator()
            $ILGen.Emit([Reflection.Emit.Opcodes]::Ldc_I4_1)
            $ILGen.Emit([Reflection.Emit.Opcodes]::Ret)
            $TypeBuilder.CreateType() | Out-Null

            # Disable SSL certificate validation
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object IgnoreCerts
        }

        $SessionProps = New-Object -TypeName System.Collections.Specialized.OrderedDictionary

        foreach($computer in $ComputerName)
        {
            $URI = "https://$($computer):8834"
            $RestMethodParams = @{
                'Method' = 'Post'
                'URI' =  "$($URI)/session"
                'Body' = @{'username' = $Credentials.UserName; 'password' = $Credentials.GetNetworkCredential().password}
                'ErrorVariable' = 'NessusLoginError'
            }

            $TokenResponse = Invoke-RestMethod @RestMethodParams
            if ($TokenResponse)
            {
                $SessionProps.add('URI', $URI)
                $SessionProps.Add('Credentials',$Credentials)
                $SessionProps.add('Token',$TokenResponse.token)
                $SessionIndex = $Global:NessusConn.Count
                $SessionProps.Add('SessionId', $SessionIndex)
                $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                $sessionobj.pstypenames[0] = 'Nessus.Session'
                
                [void]$Global:NessusConn.Add($sessionobj) 

                $sessionobj
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Get one or more current Nessus Sessions.
.DESCRIPTION
   Get one or more current Nessus Sessions.
.EXAMPLE
    Get-NessusSession


    Id    : 0
    URI   : https://192.168.1.205:8834
    Token : 50168808199c1a2197d180fa62fb9cc3cb9108054911476a

    Id    : 1
    URI   : https://192.168.1.205:8834
    Token : 2683f239b257c7729a9b501a2b916c7022a730d20b536c12

.EXAMPLE
    Get-NessusSession -SessionId 1

    Id    : 1
    URI   : https://192.168.1.205:8834
    Token : 2683f239b257c7729a9b501a2b916c7022a730d20b536c12
#>
function Get-NessusSession
{
    [CmdletBinding()]
    param(

        # Nessus session Id
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Index',
                   Position=0)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @()
    )

    Begin{}
    Process
    {
        if ($Index.Count -gt 0)
        {
            foreach($i in $SessionId)
            {
                foreach($Connection in $Global:NessusConn)
                {
                    if ($Connection.SessionId -eq $i)
                    {
                        $Connection
                    }
                }
            }
        }
        else
        {
            # Return all sessions.
            $return_sessions = @()
            foreach($s in $Global:NessusConn){$s}
        }
    }
    End{}
}


<#
.Synopsis
   Closes one or more Nessus Sessions.
.DESCRIPTION
   Closes one or more Nessus Sessions.
.EXAMPLE
    Remove-NessusSession -Id 1 -Verbose
    VERBOSE: Removing server session 1
    VERBOSE: Disposing of connection
    VERBOSE: DELETE https://192.168.1.205:8834/session with 0-byte payload
    VERBOSE: received 4-byte response of content type application/json
    VERBOSE: Removing session from $Global:NessusConn
    VERBOSE: Session 1 removed.

#>
function Remove-NessusSession
{
    [CmdletBinding()]
    param(

        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @()
    )

    Begin{}
    Process
    {
        # Finding and saving sessions in to a different Array so they can be
        # removed from the main one so as to not generate an modification
        # error for a collection in use.
        $connections = $Global:NessusConn
        $toremove = New-Object -TypeName System.Collections.ArrayList
        
        if ($Id.Count -gt 0)
        {
            foreach($i in $SessionId)
            {
                Write-Verbose -Message "Removing server session $($i)"
                
                foreach($Connection in $connections)
                {
                    if ($Connection.SessionId -eq $i)
                    {
                        [void]$toremove.Add($Connection)
                    }
                }
            }

            foreach($Connection in $toremove)
            {
                Write-Verbose -Message 'Disposing of connection'
                $RestMethodParams = @{
                    'Method'        = 'Delete'
                    'URI'           =  "$($connection.URI)/session"
                    'Headers'       = @{'X-Cookie' = "token=$($Connection.Token)"}
                    'ErrorVariable' = 'DisconnectError'
                    'ErrorAction' = 'SilentlyContinue'
                }
                $RemoveResponse = Invoke-RestMethod @RestMethodParams
                if ($DisconnectError -is [psobject])
                {
                    Write-Verbose -Message "Session with Id $($connection.Id) seems to have expired."
                }
                Write-Verbose -message "Removing session from `$Global:NessusConn"
                $Global:NessusConn.Remove($Connection)
                Write-Verbose -Message "Session $($i) removed."
            }
         }
    }
    End{}
}


<#
.Synopsis
   Get detailed information on one or more Nessus Sessions.
.DESCRIPTION
   Get detailed information on one or more Nessus Sessions.
.EXAMPLE
    Get-NessusSessionInfo -SessionId 0 -Verbose
    VERBOSE: Removing server session 0
    VERBOSE: GET https://192.168.1.205:8834/session with 0-byte payload
    VERBOSE: received 196-byte response of content type application/json


    Id         : 2
    Name       : carlos
    UserName   : carlos
    Email      : 
    Type       : local
    Permission : Sysadmin
    LastLogin  : 2/23/2015 8:58:49 PM
    Groups     : 
    Connectors : 
#>
function Get-NessusSessionInfo
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]$SessionId = @()
    )

    Begin
    {
         $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    }
    Process
    {
        $connections = $Global:NessusConn
        $ToProcess = New-Object -TypeName System.Collections.ArrayList

        foreach($i in $SessionId)
        {
            Write-Verbose "Removing server session $($i)"
                
            foreach($Connection in $connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    [void]$ToProcess.Add($Connection)
                }
            }

            foreach ($Connection in $ToProcess)
            {
                $RestMethodParams = @{
                    'Method'        = 'Get'
                    'URI'           =  "$($connection.URI)/session"
                    'Headers'       = @{'X-Cookie' = "token=$($Connection.Token)"}
                    'ErrorVariable' = 'NessusSessionError'
                }
                $SessInfo = Invoke-RestMethod @RestMethodParams
                if($SessInfo -is [psobject])
                {
                    $SessionProps = [ordered]@{}
                    $SessionProps.Add('Id', $SessInfo.id)
                    $SessionProps.Add('Name', $SessInfo.name)
                    $SessionProps.Add('UserName', $SessInfo.UserName)
                    $SessionProps.Add('Email', $SessInfo.Email)
                    $SessionProps.Add('Type', $SessInfo.Type)
                    $SessionProps.Add('Permission', $PermissionsId2Name[$SessInfo.permissions])
                    $SessionProps.Add('LastLogin', $origin.AddSeconds($SessInfo.lastlogin).ToLocalTime())
                    $SessionProps.Add('Groups', $SessInfo.groups)
                    $SessionProps.Add('Connectors', $SessInfo.connectors)

                    $SessInfoObj = New-Object -TypeName psobject -Property $SessionProps
                    $SessInfoObj.pstypenames[0] = 'Nessus.SessionInfo'
                    $SessInfoObj
                }
            }
        }
    }
    End{}
}

#endregion

#region Server
####################################################################

<#
.Synopsis
   Get information on a Nessus Server for a given session.
.DESCRIPTION
   Get information on a Nessus Server for a given session.
.EXAMPLE
    Get-NessusServerInfo -SessionId 0 -Verbose
    VERBOSE: GET https://192.168.1.205:8834/server/properties with 0-byte payload
    VERBOSE: received 478-byte response of content type application/json


    loaded_plugin_set : 201502021615
    server_uuid       : 9b7b6864-d654-345f-57f2-aeaa5438654421ba99bb9f34e2b5
    update            : @{href=; new_version=0; restart=0}
    expiration        : 1505793600
    nessus_ui_version : 6.0.2
    nessus_type       : Nessus
    notifications     : {}
    expiration_time   : 959
    capabilities      : @{multi_scanner=True; report_email_config=False}
    plugin_set        : 201502021615
    idle_timeout      : 
    scanner_boottime  : 1422920519
    login_banner      : 
    server_version    : 6.0.2
    feed              : ProFeed
#>
function Get-NessusServerInfo
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]$SessionId = @()
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
                
            $ServerInfo = InvokeNessusRestRequest -SessionObject $Connection -Path '/server/properties' -Method 'Get'
                 
            if ($ServerInfo -is [psobject])
            {
                $SrvInfoProp = [ordered]@{}
                $SrvInfoProp.Add('NessusType', $ServerInfo.nessus_type)
                $SrvInfoProp.Add('ServerVersion', $ServerInfo.server_version)
                $SrvInfoProp.Add('UIVersion', $ServerInfo.nessus_ui_version)
                $SrvInfoProp.Add('PluginSet', $ServerInfo.loaded_plugin_set)
                $SrvInfoProp.Add('Feed', $ServerInfo.feed)
                $SrvInfoProp.Add('FeedExpiration', $origin.AddSeconds($ServerInfo.expiration).ToLocalTime())
                $SrvInfoProp.Add('Capabilities', $ServerInfo.capabilities)
                $SrvInfoProp.Add('UUID', $ServerInfo.server_uuid)
                $SrvInfoProp.Add('Update', $ServerInfo.update)
                $SrvInfoObj = New-Object -TypeName psobject -Property $SrvInfoProp
                $SrvInfoObj.pstypenames[0] = 'Nessus.ServerInfo'
                $SrvInfoObj
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Get the current status of the Nessus Server for a session.
.DESCRIPTION
   Get the current status of the Nessus Server for a session.
.EXAMPLE
   Get-NessusServerStatus -Id 0


    Progress : 
    Status   : ready
#>

function Get-NessusServerStatus
{
    [CmdletBinding()]
    Param
    (
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
                
            $ServerStatus = InvokeNessusRestRequest -SessionObject $Connection -Path '/server/status' -Method 'Get'
                 
            if ($ServerStatus -is [psobject])
            {
                $ServerStatus.pstypenames[0] = 'Nessus.ServerStatus'
                $ServerStatus
            }
        }
    }
    End
    {
    }
}

#endregion

#region User
####################################################################

<#
.Synopsis
   Get a information about the Nessus User for a Session.
.DESCRIPTION
   Get a information about the Nessus User for a Session.
.EXAMPLE
    Get-NessusUser -SessionId 0 -Verbose
    VERBOSE: GET https://192.168.1.205:8834/users with 0-byte payload
    VERBOSE: received 125-byte response of content type application/json


    Name       : carlos
    UserName   : carlos
    Email      : 
    Id         : 2
    Type       : local
    Permission : Sysadmin
    LastLogin  : 2/15/2015 4:52:56 PM
#>
function Get-NessusUser
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
                
            $Users = InvokeNessusRestRequest -SessionObject $Connection -Path '/users' -Method 'Get'
                 
            if ($Users  -is [psobject])
            {
                $Users.users | ForEach-Object -Process {
                    $UserProperties = [ordered]@{}
                    $UserProperties.Add('Name', $_.name)
                    $UserProperties.Add('UserName', $_.username)
                    $UserProperties.Add('Email', $_.email)
                    $UserProperties.Add('Id', $_.id)
                    $UserProperties.Add('Type', $_.type)
                    $UserProperties.Add('Permission', $PermissionsId2Name[$_.permissions])
                    $UserProperties.Add('LastLogin', $origin.AddSeconds($_.lastlogin).ToLocalTime())
                    $UserObj = New-Object -TypeName psobject -Property $UserProperties
                    $UserObj.pstypenames[0] = 'Nessus.User'
                    $UserObj
                }
            }
        }
        
    }
    End{}
}


<#
.Synopsis
   Add a new user to a Nessus Server.
.DESCRIPTION
   Add a new user to a Nessus Server.
.EXAMPLE
   New-NessusUser -SessionId 0 -Credential (Get-Credential) -Permission Sysadmin
#>
function New-NessusUser
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

        # Credentials for connecting to the Nessus Server
        [Parameter(Mandatory=$true,
        Position=1)]
        [Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory=$true,
        Position=2)]
        [ValidateSet('Read-Only', 'Regular', 'Administrator', 'Sysadmin')]
        [string]
        $Permission,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Local', 'LDAP')]
        [string]
        $Type = 'Local',

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true)]
        [string]
        $Email,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true)]
        [string]
        $Name 

    )

    Begin{}
    Process
    {
         $ToProcess = @()

        foreach($i in $Id)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.Id -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }

        foreach($Connection in $ToProcess)
        {
            $NewUserParams = @{}

            $NewUserParams.Add('type',$Type.ToLower())
            $NewUserParams.Add('permissions', $PermissionsName2Id[$Permission])
            $NewUserParams.Add('username', $Credential.GetNetworkCredential().UserName)
            $NewUserParams.Add('password', $Credential.GetNetworkCredential().Password)

            if ($Email.Length -gt 0)
            {
                $NewUserParams.Add('email', $Email)
            }

            if ($Name.Length -gt 0)
            {
                $NewUserParams.Add('name', $Name)
            }

            $NewUser = InvokeNessusRestRequest -SessionObject $Connection -Path '/users' -Method 'Post' -Parameter $NewUserParams
                 
            if ($NewUser)
            {
                $NewUser
            }
        }
    }
    End{}
}

#endregion

#region Folders
####################################################################

<#
.Synopsis
   Gets folders configured on a Nessus Server.
.DESCRIPTION
   Gets folders configured on a Nessus Server.
.EXAMPLE
    Get-NessusFolder 0

    Name    : My Scans
    Id      : 2
    Type    : main
    Default : 1
    Unread  : 5

    Name    : Trash
    Id      : 3
    Type    : trash
    Default : 0
    Unread  : 

    Name    : Test Folder 2
    Id      : 10
    Type    : custom
    Default : 0
    Unread  : 0
#>
function Get-NessusFolder
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
            $Folders =  InvokeNessusRestRequest -SessionObject $Connection -Path '/folders' -Method 'Get'

            if ($Folders -is [psobject])
            {
                foreach ($folder in $Folders.folders)
                {
                    $FolderProps = [ordered]@{}
                    $FolderProps.Add('Name', $folder.name)
                    $FolderProps.Add('Id', $folder.id)
                    $FolderProps.Add('Type', $folder.type)
                    $FolderProps.Add('Default', $folder.default_tag)
                    $FolderProps.Add('Unread', $folder.unread_count)
                    $FolderObj = New-Object -TypeName psobject -Property $FolderProps
                    $FolderObj.pstypenames[0] = 'Nessus.Folder'
                    $FolderObj
                }
            }
        }
    }
    End
    {
    }
}

#endregion

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

#region Policy
##################################

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
function Get-NessusPolicy
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
            $Policies =  InvokeNessusRestRequest -SessionObject $Connection -Path '/policies' -Method 'Get'

            if ($Policies -is [psobject])
            {
                $Policies.policies
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
function Get-NessusPolicyTemplate
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
            $Templates =  InvokeNessusRestRequest -SessionObject $Connection -Path '/editor/policy/templates' -Method 'Get'

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
                    $Tmplobj.pstypenames[0] = 'Nessus.PolicyTemplate'
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

# Supporting Functions
##################################

function InvokeNessusRestRequest
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        $SessionObject,

        [Parameter(Mandatory=$false)]
        [hashtable]$Parameter,

        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [String]$Method,

        [Parameter(Mandatory=$false)]
        [String]$OutFile,

        [Parameter(Mandatory=$false)]
        [String]$ContentType,

        [Parameter(Mandatory=$false)]
        [String]$InFile

    )

    

    $RestMethodParams = @{
        'Method'        = $Method
        'URI'           =  "$($SessionObject.URI)$($Path)"
        'Headers'       = @{'X-Cookie' = "token=$($SessionObject.Token)"}
        'ErrorVariable' = 'NessusUserError'
    }

    if ($Parameter)
    {
        $RestMethodParams.Add('Body', $Parameter)
    }

    if($OutFile)
    {
        $RestMethodParams.add('OutFile', $OutFile)
    }

    if($ContentType)
    {
        $RestMethodParams.add('ContentType', $ContentType)
    }

    if($InFile)
    {
        $RestMethodParams.add('InFile', $InFile)
    }

    try
    {
        #$RestMethodParams.Uri
        $Results = Invoke-RestMethod @RestMethodParams
   
    }
    catch [Net.WebException] 
    {
        [int]$res = $_.Exception.Response.StatusCode
        if ($res -eq 401)
        {
            # Request failed. More than likely do to time-out.
            # Re-Authenticating using information from session.
            write-verbose -Message 'The session has expired, Re-authenticating'
            $ReAuthParams = @{
                'Method' = 'Post'
                'URI' =  "$($SessionObject.URI)/session"
                'Body' = @{'username' = $SessionObject.Credentials.UserName; 'password' = $SessionObject.Credentials.GetNetworkCredential().password}
                'ErrorVariable' = 'NessusLoginError'
                'ErrorAction' = 'SilentlyContinue'
            }

            $TokenResponse = Invoke-RestMethod @ReAuthParams

            if ($NessusLoginError)
            {
                Write-Error -Message 'Failed to Re-Authenticate the session. Session is being Removed.'
                $FailedConnection = $SessionObject
                [void]$Global:NessusConn.Remove($FailedConnection)
            }
            else
            {
                Write-Verbose -Message 'Updating session with new authentication token.'

                # Creating new object with updated token so as to replace in the array the old one.
                $SessionProps = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
                $SessionProps.add('URI', $SessionObject.URI)
                $SessionProps.Add('Credentials',$SessionObject.Credentials)
                $SessionProps.add('Token',$TokenResponse.token)
                $SessionProps.Add('SessionId', $SessionObject.SessionId)
                $Sessionobj = New-Object -TypeName psobject -Property $SessionProps
                $Sessionobj.pstypenames[0] = 'Nessus.Session'
                [void]$Global:NessusConn.Remove($SessionObject)
                [void]$Global:NessusConn.Add($Sessionobj)

                # Re-submit query with the new token and return results.
                $RestMethodParams.Headers = @{'X-Cookie' = "token=$($Sessionobj.Token)"}
                $Results = Invoke-RestMethod @RestMethodParams
            }
        }
        else
        {
            write-error -ErrorRecord $_ 
        }
    }
    $Results
}

