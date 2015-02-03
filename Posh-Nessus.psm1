if (!(Test-Path variable:Global:NessusConn ))
{
    $Global:NessusConn = New-Object System.Collections.ArrayList
}
 

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
                $SessionProps.Add('Id', $SessionIndex)
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
    Get-NessusSession -Id 1


    Id    : 0
    URI   : https://192.168.1.205:8834
    Token : 50168808199c1a2197d180fa62fb9cc3cb9108054911476a

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
        $Id = @()
    )

    Begin{}
    Process
    {
        if ($Index.Count -gt 0)
        {
            foreach($i in $Id)
            {
                foreach($Connection in $Global:NessusConn)
                {
                    if ($Connection.Index -eq $i)
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
        $Id = @()
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
            foreach($i in $Id)
            {
                Write-Verbose -Message "Removing server session $($i)"
                
                foreach($Connection in $connections)
                {
                    if ($Connection.Id -eq $i)
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
                if ($DisconnectError)
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
    Get-NessusSessionInfo -Id 0 -Verbose
    VERBOSE: Removing server session 0
    VERBOSE: GET https://192.168.1.205:8834/session with 0-byte payload
    VERBOSE: received 196-byte response of content type application/json


    lockout          : 0
    whatsnew         : True
    container_id     : 0
    groups           : 
    whatsnew_version : 
    lastlogin        : 1422921992
    permissions      : 128
    type             : local
    name             : carlos
    email            : 
    username         : carlos
    id               : 2
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
        [int32[]]$Id = @()
    )

    Begin
    {
    }
    Process
    {
        $connections = $Global:NessusConn
        $ToProcess = New-Object -TypeName System.Collections.ArrayList

        foreach($i in $Id)
        {
            Write-Verbose "Removing server session $($i)"
                
            foreach($Connection in $connections)
            {
                if ($Connection.Id -eq $i)
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
                Invoke-RestMethod @RestMethodParams
            }
        }
    }
    End
    {
    }
}


# Server
####################################################################

<#
.Synopsis
   Get information on a Nessus Server for a given session.
.DESCRIPTION
   Get information on a Nessus Server for a given session.
.EXAMPLE
    Get-NessusServerInfo -Id 0 -Verbose
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
        [int32[]]$Id = @()
    )

    Begin
    {
    }
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
                
            $ServerInfo = InvokeNessusRestRequest -SessionObject $Connection -Path '/server/properties' -Method 'Get'
                 
            if ($ServerInfo)
            {
                $ServerInfo
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
        $Id = @()
    )

    Begin
    {
    }
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
                
            $ServerStatus = InvokeNessusRestRequest -SessionObject $Connection -Path '/server/status' -Method 'Get'
                 
            if ($ServerStatus)
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


# USER
####################################################################

<#
.Synopsis
   Get a information about the Nessus User for a Session.
.DESCRIPTION
   Get a information about the Nessus User for a Session.
.EXAMPLE
    Get-NessusUser -Id 0 -Verbose
    VERBOSE: GET https://192.168.1.205:8834/users with 0-byte payload
    VERBOSE: received 125-byte response of content type application/json


    lastlogin   : 1422921992
    permissions : 128
    type        : local
    name        : carlos
    email       : 
    username    : carlos
    id          : 2
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
        [int32[]]$Id = @()
    )

    Begin
    {
        
    }
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
                
            $Users = InvokeNessusRestRequest -SessionObject $Connection -Path '/users' -Method 'Get'
                 
            if ($Users)
            {
                $Users.users
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
        [int32[]]$Id = @(),

        # Credentials for connecting to the Nessus Server
        [Parameter(Mandatory=$true,
        Position=1)]
        [Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$Type = 'Local'
    )

    Begin
    {
    }
    Process
    {
    }
    End
    {
    }
}


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
        [String]$Method
    )

    $RestMethodParams = @{
        'Method'        = $Method
        'URI'           =  "$($SessionObject.URI)$($Path)"
        'Headers'       = @{'X-Cookie' = "token=$($SessionObject.Token)"}
        'ErrorVariable' = 'NessusUserError'
    }

    if ($Parameter)
    {
        $RestMethodParams.Add($Body, $Parameter)
    }
    try
    {
        $Results = Invoke-RestMethod @RestMethodParams
    }
    catch [Net.WebException] 
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
            $SessionProps.Add('Id', $SessionObject.Id)
            $Sessionobj = New-Object -TypeName psobject -Property $SessionProps
            $Sessionobj.pstypenames[0] = 'Nessus.Session'
            [void]$Global:NessusConn.Remove($SessionObject)
            [void]$Global:NessusConn.Add($Sessionobj)

            # Re-submit query with the new token and return results.
            $RestMethodParams.Headers = @{'X-Cookie' = "token=$($Sessionobj.Token)"}
            $Results = Invoke-RestMethod @RestMethodParams
        }
    }
    $Results
}