if (!(Test-Path variable:Global:NessusConn ))
{
    $Global:NessusConn = New-Object System.Collections.ArrayList
}
 
 # Variables
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

 # Load Functions

 . .\User.ps1
 . .\Session.ps1
 . .\Policy.ps1
 . .\Scan.ps1
 . .\Folders.ps1
 . .\Server.ps1


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

