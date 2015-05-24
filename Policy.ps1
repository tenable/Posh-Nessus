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
    [CmdletBinding(DefaultParameterSetName = 'All')]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true,
                   ParameterSetName = 'All')]
        [Parameter(ParameterSetName = 'ByName')]
        [Parameter(ParameterSetName = 'ByID')]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory = $false,
                   Position = 1,
                   ValueFromPipelineByPropertyName = $true,
                   ParameterSetName = 'ByName')]
        [string]
        $Name,

        [Parameter(Mandatory = $false,
                   Position = 1,
                   ValueFromPipelineByPropertyName = $true,
                   ParameterSetName = 'ByID')]
        [string]
        $PolicyID
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
                switch ($PSCmdlet.ParameterSetName)
                {
                    'ByName' 
                    {
                        $Policies2Proc = $Policies.policies | Where-Object {$_.name -eq $Name}
                    }
                
                    'ByID' 
                    {
                        $Policies2Proc = $Policies.policies | Where-Object {$_.id -eq $PolicyID}
                    }

                    'All'
                    {
                        $Policies2Proc = $Policies.policies
                    }
                }

                foreach($Policy in $Policies2Proc)
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
    [CmdletBinding(DefaultParameterSetName = 'All')]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory = $true,
                   Position = 0,
                   ValueFromPipelineByPropertyName = $true,
                   ParameterSetName = 'All')]
        [Parameter(ParameterSetName = 'ByName')]
        [Parameter(ParameterSetName = 'ByUUID')]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory = $false,
                   Position = 1,
                   ValueFromPipelineByPropertyName = $true,
                   ParameterSetName = 'ByName')]
        [string]
        $Name,

        [Parameter(Mandatory = $false,
                   Position = 1,
                   ValueFromPipelineByPropertyName = $true,
                   ParameterSetName = 'ByUUID')]
        [string]
        $PolicyUUID

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
                switch ($PSCmdlet.ParameterSetName)
                {
                    'ByName' 
                    {
                        $Templates2Proc = $Templates.templates | Where-Object {$_.name -eq $Name}
                    }
                
                    'ByUUID' 
                    {
                        $Templates2Proc = $Templates.templates | Where-Object {$_.uuid -eq $PolicyUUID}
                    }

                    'All'
                    {
                        $Templates2Proc = $Templates.templates
                    }
                }
                
                foreach($Template in $Templates2Proc)
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
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName = 'ByName')]
        [Parameter(ParameterSetName = 'ByID')]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true,
                   ParameterSetName = 'ByID')]
        [int32]
        $PolicyId,

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true,
                   ParameterSetName = 'ByName')]
        [string]
        $Name
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
            switch ($PSCmdlet.ParameterSetName)
            {
                'ByName' 
                {
                    $Pol = Get-NessusPolicy -Name $Name -SessionId $Connection.SessionId
                    if ($Pol -ne $null)
                    {
                        $PolicyId = $Pol.PolicyId
                    }
                    else
                    {
                        throw "Policy with name $($Name) was not found."
                    }
                }
                
            }
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
   Create a new policy based on a policy template.
.DESCRIPTION
   Create a new policy based on a policy template.
.EXAMPLE
   New-NessusPolicy -SessionId 0 -Name "Dev Lab Scan Policy" -TemplateName advanced -Description "Policy for scanning devlopment lab"


    Name           : Dev Lab Scan Policy
    PolicyId       : 123
    Description    : Policy for scanning devlopment lab
    PolicyUUID     : ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66
    Visibility     : private
    Shared         : False
    Owner          : carlos
    UserId         : 2
    NoTarget       : false
    UserPermission : 128
    Modified       : 5/21/2015 11:35:20 PM
    Created        : 5/21/2015 11:35:20 PM
    SessionId      : 0

#>
function New-NessusPolicy
{
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    Param
    (
        # Nessus session Id.
        [Parameter(Mandatory = $true,
                   Position = 0,
                   ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'ByName')]
        [Parameter(ParameterSetName = 'ByUUID')]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        # Name for new policy.
        [Parameter(Mandatory = $true,
                   Position = 1,
                   ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'ByName')]
        [Parameter(ParameterSetName = 'ByUUID')]
        [string]
        $Name,

        # Policy Template UUID to base new policy from.
        [Parameter(Mandatory = $true,
                   Position = 2,
                   ValueFromPipelineByPropertyName = $true,
                   ParameterSetName = 'ByUUID')]
        [string]
        $PolicyUUID,

        # Policy Template name to base new policy from.
        [Parameter(Mandatory = $true,
                   Position = 2,
                   ValueFromPipelineByPropertyName = $true,
                   ParameterSetName = 'ByName')]
        [string]
        $TemplateName,

        # Description for new policy.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'ByName')]
        [Parameter(ParameterSetName = 'ByUUID')]
        [string]
        $Description = ''
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
            switch ($PSCmdlet.ParameterSetName)
            {
                'ByName' 
                {
                    $tmpl = Get-NessusPolicyTemplate -Name $TemplateName -SessionId $Connection.SessionId
                    if ($tmpl -ne $null)
                    {
                        $PolicyUUID = $tmpl.PolicyUUID
                    }
                    else
                    {
                        throw "Template with name $($TemplateName) was not found."
                    }
                }
                
                'ByUUID' 
                {
                    $Templates2Proc = $Templates.templates | Where-Object {$_.uuid -eq $PolicyUUID}
                }
            }

            
            $RequestSet = @{'uuid' = $PolicyUUID; 
                'settings' = @{
                    'name' = $Name
                    'description' = $Description}
            }

            $SettingsJson = ConvertTo-Json -InputObject $RequestSet -Compress
            $RequestParams = @{
                'SessionObject' = $Connection
                'Path' = "/policies/"
                'Method' = 'POST'
                'ContentType' = 'application/json'
                'Parameter'= $SettingsJson
            }
            $NewPolicy = InvokeNessusRestRequest @RequestParams
            Get-NessusPolicy -PolicyID $NewPolicy.policy_id -SessionId $Connection.sessionid
        }
    }
    End
    {
    }
}
#endregion