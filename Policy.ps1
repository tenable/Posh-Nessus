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
                foreach($Policy in $Policies.policies)
                {
                    $PolProps = [ordered]@{}
                    $PolProps.Add('Name', $Policy.Name)
                    $PolProps.Add('PolicyId', $Policy.id)
                    $PolProps.Add('Description', $Policy.description)
                    $PolProps.Add('TemplateUUID', $Policy.template_uuid)
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
                    $TmplProps.add('UUID', $Template.uuid)
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
#endregion