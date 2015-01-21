if (!(Test-Path variable:Global:NessusConn ))
{
    $Global:NessusConn = New-Object System.Collections.ArrayList
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
        [int32[]]$Id = @()
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
        [int32[]]$Id = @()
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
                        $toremove.Add($Connection)
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
                
            foreach($Connection in connections)
            {
                if ($Connection.Id -eq $i)
                {
                    $ToProcess.Add($Connection)
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
                
            $ServerStatus = InvokeNessusRestRequest -SessionObject $Connection -Path '/server/status' -Method 'Get'
                 
            if ($ServerStatus)
            {
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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