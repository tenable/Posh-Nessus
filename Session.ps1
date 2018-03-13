
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
    [CmdletBinding(DefaultParameterSetName='Credentials')]
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
                   Position=1,
                   ParameterSetName='Credentials')]
        [Management.Automation.PSCredential]$Credentials,

        # API keys (alternative to Credentials)
        [Parameter(Mandatory=$true,
                   Position=1,
                   ParameterSetName='API')]
        [String]$AccessKey,

        [Parameter(Mandatory=$true,
                   Position=2,
                   ParameterSetName='API')]
        [String]$SecretKey
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
            $URI = "https://$($computer):$($Port)"

            # Generate a session if credentials are used
            if ($Credentials) {
                $RestMethodParams = @{
                    'Method' = 'Post'
                    'URI' =  "$($URI)/session"
                    'Body' = @{'username' = $Credentials.UserName; 'password' = $Credentials.GetNetworkCredential().password}
                    'ErrorVariable' = 'NessusLoginError'
                }
                $TokenResponse = Invoke-RestMethod @RestMethodParams
                if ($TokenResponse) {
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
            # Generate a pseudo-session if API keys are provided and work
            elseif ($AccessKey -and $SecretKey) {
                $RestMethodParams = @{
                    'Method' = 'Get'
                    'URI' =  "$($URI)"
                    'Headers' = @{'X-ApiKeys' = "accessKey=$accessKey; secretKey=$secretKey"}
                    'ErrorVariable' = 'NessusLoginError'
                }
                $null = Invoke-RestMethod @RestMethodParams
                if (!$NessusLoginError) {
                    $SessionProps.add('URI', $URI)
                    $SessionProps.Add('Token',@{
                        AccessKey = $AccessKey
                        SecretKey = $SecretKey
                    })
                    $SessionIndex = $Global:NessusConn.Count
                    $SessionProps.Add('SessionId', $SessionIndex)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = 'Nessus.Session'

                    [void]$Global:NessusConn.Add($sessionobj)

                    $sessionobj
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

        if ($SessionId.Count -gt 0)
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
                try
                {
                    $RemoveResponse = Invoke-RestMethod @RestMethodParams
                }
                catch
                {
                    Write-Verbose -Message "Session with Id $($connection.SessionId) seems to have expired."
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
