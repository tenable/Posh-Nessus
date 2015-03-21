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
function Get-NessusGroup
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
        $SessionId = @()
    )

    Begin
    {
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
            $ServerTypeParams = @{
                'SessionObject' = $Connection
                'Path' = '/server/properties'
                'Method' = 'GET'
            }

            $Server =  InvokeNessusRestRequest @ServerTypeParams

            if ($Server.capabilities.multi_user -eq 'full')
            {
                $GroupParams = @{
                    'SessionObject' = $Connection
                    'Path' = '/groups'
                    'Method' = 'GET'
                }

                $Groups =  InvokeNessusRestRequest @GroupParams
                foreach($Group in $Groups.groups)
                {
                    $GroupProps = [ordered]@{}
                    $GroupProps.Add('Name', $Group.name)
                    $GroupProps.Add('GroupId', $Group.id)
                    $GroupProps.Add('Permissions', $Group.permissions)
                    $GroupProps.Add('UserCount', $Group.user_count)
                    $GroupProps.Add('SessionId', $Connection.SessionId)
                    $GroupObj = [PSCustomObject]$GroupProps
                    $GroupObj.pstypenames.insert(0,'Nessus.Group')
                    $GroupObj
                }
            }
            else
            {
                Write-Warning -message "Server for session $($Connection.sessionid) is not licenced for multiple users."
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
function New-NessusGroup
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
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [string]
        $Name
    )

    Begin
    {
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
            $ServerTypeParams = @{
                'SessionObject' = $Connection
                'Path' = '/server/properties'
                'Method' = 'GET'
            }

            $Server =  InvokeNessusRestRequest @ServerTypeParams

            if ($Server.capabilities.multi_user -eq 'full')
            {
                $Groups =  InvokeNessusRestRequest -SessionObject $Connection -Path '/groups' -Method 'POST' -Parameter @{'name' = $Name}
                $NewGroupProps = [ordered]@{}
                $NewGroupProps.Add('Name', $Groups.name)
                $NewGroupProps.Add('GroupId', $Groups.id)
                $NewGroupProps.Add('Permissions', $Groups.permissions)
                $NewGroupProps.Add('SessionId', $Connection.SessionId)
                $NewGroupObj = [pscustomobject]$NewGroupProps
                $NewGroupObj
            }
            else
            {
                Write-Warning -message "Server for session $($Connection.sessionid) is not licenced for multiple users."
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
function Remove-NessusGroup
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
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [Int32]
        $GroupId
    )

    Begin
    {
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
            $ServerTypeParams = @{
                'SessionObject' = $Connection
                'Path' = '/server/properties'
                'Method' = 'GET'
            }

            $Server =  InvokeNessusRestRequest @ServerTypeParams

            if ($Server.capabilities.multi_user -eq 'full')
            {
                $GroupParams = @{
                    'SessionObject' = $Connection
                    'Path' = "/groups/$($GroupId)"
                    'Method' = 'DELETE '
                }

                InvokeNessusRestRequest @GroupParams   
            }
            else
            {
                Write-Warning -message "Server for session $($Connection.sessionid) is not licenced for multiple users."
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
function Add-NessusGroupUser
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
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [Int32]
        $GroupId,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [Int32]
        $UserId
    )

    Begin
    {
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
            $ServerTypeParams = @{
                'SessionObject' = $Connection
                'Path' = '/server/properties'
                'Method' = 'GET'
            }

            $Server =  InvokeNessusRestRequest @ServerTypeParams

            if ($Server.capabilities.multi_user -eq 'full')
            {
                $GroupParams = @{
                    'SessionObject' = $Connection
                    'Path' = "/groups/$($GroupId)/users"
                    'Method' = 'POST'
                    'Parameter' = @{'user_id' = $UserId}
                }

                InvokeNessusRestRequest @GroupParams   
            }
            else
            {
                Write-Warning -message "Server for session $($Connection.sessionid) is not licenced for multiple users."
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
function Remove-NessusGroupUser
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
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [Int32]
        $GroupId,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [Int32]
        $UserId
    )

    Begin
    {
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
            $ServerTypeParams = @{
                'SessionObject' = $Connection
                'Path' = '/server/properties'
                'Method' = 'GET'
            }

            $Server =  InvokeNessusRestRequest @ServerTypeParams

            if ($Server.capabilities.multi_user -eq 'full')
            {
                $GroupParams = @{
                    'SessionObject' = $Connection
                    'Path' = "/groups/$($GroupId)/users/$($UserId)"
                    'Method' = 'DELETE'
                }

                InvokeNessusRestRequest @GroupParams   
            }
            else
            {
                Write-Warning -message "Server for session $($Connection.sessionid) is not licenced for multiple users."
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
function Rename-NessusGroup
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
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [Int32]
        $GroupId,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [string]
        $Name
    )

    Begin
    {
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
            $ServerTypeParams = @{
                'SessionObject' = $Connection
                'Path' = '/server/properties'
                'Method' = 'GET'
            }

            $Server =  InvokeNessusRestRequest @ServerTypeParams

            if ($Server.capabilities.multi_user -eq 'full')
            {
                $GroupParams = @{
                    'SessionObject' = $Connection
                    'Path' = "/groups/$($GroupId)"
                    'Method' = 'PUT'
                    'ContentType' = 'application/json'
                    'Parameter' = (ConvertTo-Json -InputObject @{'name' = $Name} -Compress)
                }

                InvokeNessusRestRequest @GroupParams   
            }
            else
            {
                Write-Warning -message "Server for session $($Connection.sessionid) is not licenced for multiple users."
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
function Show-NessusGroupMember
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
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [Int32]
        $GroupId
    )

    Begin
    {
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
            $ServerTypeParams = @{
                'SessionObject' = $Connection
                'Path' = '/server/properties'
                'Method' = 'GET'
            }

            $Server =  InvokeNessusRestRequest @ServerTypeParams

            if ($Server.capabilities.multi_user -eq 'full')
            {
                $GroupParams = @{
                    'SessionObject' = $Connection
                    'Path' = "/groups/$($GroupId)/users"
                    'Method' = 'GET '
                }

                $GroupMembers = InvokeNessusRestRequest @GroupParams
                foreach($User in $GroupMembers.users)
                {
                    $UserProperties = [ordered]@{}
                    $UserProperties.Add('Name', $User.name)
                    $UserProperties.Add('UserName', $User.username)
                    $UserProperties.Add('Email', $User.email)
                    $UserProperties.Add('UserId', $_Userid)
                    $UserProperties.Add('Type', $User.type)
                    $UserProperties.Add('Permission', $PermissionsId2Name[$User.permissions])
                    $UserProperties.Add('LastLogin', $origin.AddSeconds($User.lastlogin).ToLocalTime())
                    $UserProperties.Add('SessionId', $Connection.SessionId)
                    $UserObj = New-Object -TypeName psobject -Property $UserProperties
                    $UserObj.pstypenames[0] = 'Nessus.User'
                    $UserObj
                }
            }
            else
            {
                Write-Warning -message "Server for session $($Connection.sessionid) is not licenced for multiple users."
            }
        }
    }
    End
    {
    }
}