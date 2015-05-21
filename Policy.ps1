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
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
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
            $Policies =  InvokeNessusRestRequest -SessionObject $Connection -Path '/policies' -Method 'Get'

            if ($Policies -is [psobject])
            {
                foreach($Policy in $Policies.policies)
                {
                    $PolProps = [ordered]@{}
                    $PolProps.Add('Name', $Policy.Name)
                    $PolProps.Add('PolicyId', $Policy.id)
                    $PolProps.Add('Description', $Policy.description)
                    $PolProps.Add('PolicyUUID', $Policy.template_uuid)
                    $PolProps.Add('Visibility', $Policy.visibility)
                    $PolProps['Shared']  = &{ if ($Policy.shared -eq 1){$True}else{$False}}
                    $PolProps.Add('Owner', $Policy.owner)
                    $PolProps.Add('UserId', $Policy.owner_id)
                    $PolProps.Add('NoTarget', $Policy.no_target)
                    $PolProps.Add('UserPermission', $Policy.user_permissions)
                    $PolProps.Add('Modified', $origin.AddSeconds($Policy.last_modification_date).ToLocalTime())
                    $PolProps.Add('Created', $origin.AddSeconds($Policy.creation_date).ToLocalTime())
                    $PolProps.Add('SessionId', $Connection.SessionId)
                    $PolObj = [PSCustomObject]$PolProps
                    $PolObj.pstypenames.insert(0,'Nessus.Policy')
                    $PolObj
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
                    $TmplProps.add('PolicyUUID', $Template.uuid)
                    $TmplProps.add('CloudOnly', $Template.cloud_only)
                    $TmplProps.add('SubscriptionOnly', $Template.subscription_only)
                    $TmplProps.add('SessionId', $Connection.SessionId)
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
function Copy-NessusPolicy
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
        $PolicyId

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
            $CopiedPolicy =  InvokeNessusRestRequest -SessionObject $Connection -Path "/policies/$($PolicyId)/copy" -Method 'Post'
            $PolProp = [ordered]@{}
            $PolProp.Add('Name', $CopiedPolicy.name)
            $PolProp.Add('PolicyId', $CopiedPolicy.id)
            $PolProp.Add('SessionId', $Connection.SessionId)
            $CopiedObj = [PSCustomObject]$PolProp
            $CopiedObj.pstypenames.insert(0,'Nessus.PolicyCopy')
            $CopiedObj
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
function Remove-NessusPolicy
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
        $PolicyId

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
            Write-Verbose -Message "Deleting policy with id $($PolicyId)."
            $RemovedPolicy =  InvokeNessusRestRequest -SessionObject $Connection -Path "/policies/$($PolicyId)" -Method 'DELETE'
            Write-Verbose -Message 'Policy deleted.'
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
function Export-NessusPolicy
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
        $PolicyId,

        [Parameter(Mandatory=$false,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [string]
        $OutFile

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
            Write-Verbose -Message "Exporting policy with id $($PolicyId)."
            $Policy =  InvokeNessusRestRequest -SessionObject $Connection -Path "/policies/$($PolicyId)/export" -Method 'GET'
            if ($OutFile.length -gt 0)
            {
                Write-Verbose -Message "Saving policy as $($OutFile)"
                $Policy.Save($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile))
            }
            else
            {
                $Policy
            }
            Write-Verbose -Message 'Policy exported.'
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
function Import-NessusPolicy
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
        $File
    )

    Begin
    {
        
        $ContentType = 'application/octet-stream'
        $URIPath = 'file/upload'

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
                $Policy = Invoke-RestMethod -Method Post -Uri "$($Connection.URI)/policies/import" -header @{'X-Cookie' = "token=$($Connection.Token)"} -Body (ConvertTo-Json @{'file' = $fileinfo.name;} -Compress) -ContentType 'application/json'
                $PolProps = [ordered]@{}
                $PolProps.Add('Name', $Policy.Name)
                $PolProps.Add('PolicyId', $Policy.id)
                $PolProps.Add('Description', $Policy.description)
                $PolProps.Add('PolicyUUID', $Policy.template_uuid)
                $PolProps.Add('Visibility', $Policy.visibility)
                $PolProps['Shared']  = &{ if ($Policy.shared -eq 1){$True}else{$False}}
                $PolProps.Add('Owner', $Policy.owner)
                $PolProps.Add('UserId', $Policy.owner_id)
                $PolProps.Add('NoTarget', $Policy.no_target)
                $PolProps.Add('UserPermission', $Policy.user_permissions)
                $PolProps.Add('Modified', $origin.AddSeconds($Policy.last_modification_date).ToLocalTime())
                $PolProps.Add('Created', $origin.AddSeconds($Policy.creation_date).ToLocalTime())
                $PolProps.Add('SessionId', $Connection.SessionId)
                $PolObj = [PSCustomObject]$PolProps
                $PolObj.pstypenames.insert(0,'Nessus.Policy')
                $PolObj
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
function Get-NessusPolicyDetail
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
        $PolicyId
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
            Write-Verbose -Message "Getting details for policy with id $($PolicyId)."
            $Policy =  InvokeNessusRestRequest -SessionObject $Connection -Path "/policies/$($PolicyId)" -Method 'GET'
            $Policy
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
function Add-NessusPolicyFTPCred
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
        [int32]
        $PolicyId,

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]
        $Credential
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
        foreach ($Session in $ToProcess)
        {
            $RequestParams = @{
                'SessionObject' = $Session
                'Path' = "/policies/$($PolicyId)"
                'Method' = 'PUT'
                'ContentType' = 'application/json'
                'Parameter'= "{'uuid':'ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66','credentials': {'add': {'Plaintext Authentication':{'FTP':{'username':'charlie','password':'nessus@nessus.org'}}}, 'edit': {}, 'delete': {}}}"
                
            }
            InvokeNessusRestRequest @RequestParams
        }
    }
    End
    {
    }
}
#endregion