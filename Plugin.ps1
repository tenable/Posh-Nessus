
function Show-NessusPlugin
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
        $PluginId
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
            $Plugin =  InvokeNessusRestRequest -SessionObject $Connection -Path "/plugins/plugin/$($PluginId)" -Method 'Get'

            if ($Plugin -is [psobject])
            {
                if ($Plugin.name -ne $null)
                {
                    # Parse Attributes
                    $Attributes = [ordered]@{}

                    foreach($Attribute in $Plugin.attributes)
                    {
                        # Some attributes have multiple values, i.e. osvdb. This causes errors when adding duplicates
                        If ($Attributes.Keys -contains $Attribute.attribute_name)
                        {
                            $Attributes[$Attribute.attribute_name] += ", $($Attribute.attribute_value)"
                        }
                        Else
                        {
                            $Attributes.add("$($Attribute.attribute_name)", "$($Attribute.attribute_value)")
                        }
                    }
                    $PluginProps = [ordered]@{}
                    $PluginProps.Add('Name', $Plugin.name)
                    $PluginProps.Add('PluginId', $Plugin.id)
                    $PluginProps.Add('FamilyName', $Plugin.family_name)
                    $PluginProps.Add('Attributes', $Attributes)
                    $PluginProps.Add('SessionId', $Connection.SessionId)
                    $PluginObj = New-Object -TypeName psobject -Property $PluginProps
                    $PluginObj.pstypenames[0] = 'Nessus.Plugin'
                    $PluginObj
                }
                
            }
        }
    }
    
    End
    {
    
    }
}


function Get-NessusPluginFamily
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
            $Families =  InvokeNessusRestRequest -SessionObject $Connection -Path '/plugins/families' -Method 'Get'
            if ($Families -is [Object[]])
            {
                foreach ($Family in $Families)
                {
                    $FamilyProps = [ordered]@{}
                    $FamilyProps.add('Name', $Family.name)
                    $FamilyProps.add('Id', $Family.id)
                    $FamilyProps.add('Count', $Family.count)
                    $FamilyObj = New-Object -TypeName psobject -Property $FamilyProps
                    $FamilyObj.pstypenames[0] = 'Nessus.PluginFamily'
                    $FamilyObj

                }
            }
        }
    }
    End
    {
    }
}


function Show-NessusPluginFamilyDetails
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
        [int]
        $FamilyId 
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
            $FamilyDetails =  InvokeNessusRestRequest -SessionObject $Connection -Path "/plugins/families/$($FamilyId)" -Method 'Get'
            if ($FamilyDetails -is [Object])
            {
                $DetailProps = [ordered]@{}
                $DetailProps.Add('Name', $FamilyDetails.name)
                $DetailProps.Add('FamilyId', $FamilyDetails.id)
                $DetailProps.Add('Plugins', $FamilyDetails.plugins)
                $FamilyObj = New-Object -TypeName psobject -Property $DetailProps
                $FamilyObj.pstypenames[0] = 'Nessus.PluginFamilyDetails'
                $FamilyObj  
            }
        }
    }
    End
    {
    }
}


function Get-NessusPluginRule
{
    <#
            .SYNOPSIS
            Gets a list of all Nessus plugin rules

            .DESCRIPTION
            Gets a list of all Nessus plugin rules

            .PARAMETER SessionId
            ID of a valid Nessus session

            .PARAMETER Detail
            Does an additional lookup on each rule, to return the plugin name. Helpfule when reporting

            .EXAMPLE
            Get-NessusPluginRule -SessionId 0
            Gets all defined plugin rules

            .EXAMPLE
            Get-NessusPluginRule -SessionId 0 -Detail
            Gets all defined plugin rules with details

            .OUTPUTS
            Returns a PSObject with basic rule info, or returns PSObject with base info + plugin name
    #>


    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                Position=0,
        ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId,
        
        [Parameter(Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int32]
        $PluginId,
        
        [Switch]
        $Detail

    )

    Begin
    {
        
        function Limit-PluginRule
        {
            Param
            (
                [Object] 
                [Parameter(ValueFromPipeline=$true)]
                $InputObject
            )
            
            Process
            {
                if ($InputObject.Plugin_ID -eq $PluginId)
                {
                    $InputObject
                }
            }
        }
        
        $dicTypeRev = @{
            'recast_critical' = 'Critical'
            'recast_high' = 'High'
            'recast_medium' = 'Medium'
            'recast_low' = 'Low'
            'recast_info' = 'Info'
            'exclude' = 'Exclude'
        }

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
        
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    }
    
    Process
    {
        foreach($Connection in $ToProcess)
        {
            $pRules =  InvokeNessusRestRequest -SessionObject $Connection -Path '/plugin-rules' -Method 'Get'

            if ($pRules -is [psobject])
            {
                foreach($pRule in $pRules.plugin_rules)
                {
                    $dtExpiration = $null
                    
                    If ($pRule.date)
                    {
                        $dtExpiration = $origin.AddSeconds($pRule.date).ToLocalTime()
                    }
                    
                    
                    
                    $pRuleProps = [Ordered]@{}
                    $pRuleProps.add('ID', $pRule.id)
                    $pRuleProps.add('Host', $pRule.host)
                    $pRuleProps.add('PluginId', $pRule.plugin_id)
                    
                    # Significant increase in web requests!
                    If ($Detail)
                    {
                        # Provides the rule name in the returned object
                        $objPluginDetails = Show-NessusPlugin -SessionId $SessionId -PluginId $pRule.plugin_id
                        $pRuleProps.add('Plugin', $objPluginDetails.Name)
                    }
                    
                    $pRuleProps.add('Expiration', $dtExpiration)
                    $pRuleProps.add('Type', $dicTypeRev[$pRule.type])
                    $pRuleProps.add('Owner', $pRule.owner)
                    $pRuleProps.add('Owner_ID', $pRule.owner_id)
                    $pRuleProps.add('Shared', $pRule.shared)
                    $pRuleProps.add('Permissions', $pRule.user_permissions)
                    $pRuleProps.add('SessionId', $Connection.SessionId)
                    $pRuleObj = New-Object -TypeName psobject -Property $pRuleProps
                    $pRuleObj.pstypenames[0] = 'Nessus.PluginRules'

                    If ($PluginId)
                    {
                        $pRuleObj | Limit-PluginRule
                    }
                    Else
                    {
                        $pRuleObj
                    }
                }
            }
        }
    }
    
    End
    {
    
    }
}


function Add-NessusPluginRule
{
    <#
            .SYNOPSIS
            Creates a new Nessus plugin rule

            .DESCRIPTION
            Can be used to alter report output for various reasons. i.e. vulnerability acceptance, verified 
            false-positive on non-credentialed scans, alternate mitigation in place, etc...

            .PARAMETER SessionId
            ID of a valid Nessus session

            .PARAMETER PluginId
            ID number of the plugin which would you like altered

            .PARAMETER ComputerName
            Name, IP address, or Wildcard (*), which defines the the host(s) affected by the rule

            .PARAMETER Type
            Severity level you would like future scan reports to display for the defined host(s)

            .PARAMETER Expiration
            Date/Time object, which defines the time you would like the rule to expire

            .EXAMPLE
            Add-NessusPluginRule -SessionId 0 -PluginId 15901 -ComputerName 'WebServer' -Type Critical
            Creates a rule that changes the default severity of 'Medium', to 'Critical' for the defined computer and plugin ID

            .EXAMPLE
            $WebServers | % {Add-NessusPluginRule -SessionId 0 -PluginId 15901 -ComputerName $_ -Type Critical}
            Creates a rule for a list computers, using the defined options
    #>


    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true, Position=0,
        ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId,
        
        [Parameter(Mandatory=$true, Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int32]
        $PluginId,
        
        [Parameter(Mandatory=$false, Position=2,
        ValueFromPipelineByPropertyName=$true)]
        [Alias('IPAddress','IP','Host')]
        [String]
        $ComputerName = '*',
        
        [Parameter(Mandatory=$true, Position=3, 
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Critical','High','Medium','Low','Info','Exclude')]
        [String]
        $Type,
        
        [Parameter(Mandatory=$false, Position=4, 
        ValueFromPipelineByPropertyName=$true)]
        [datetime] 
        $Expiration
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
        
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    }
    
    Process
    {
        foreach($Connection in $ToProcess)
        {
            $dtExpiration = $null
                    
            If ($Expiration)
            {
                
                $dtExpiration = (New-TimeSpan -Start $origin -End $Expiration).TotalSeconds.ToInt32($null)
            }
                    
            $dicType = @{
                'Critical' = 'recast_critical'
                'High' = 'recast_high'
                'Medium' = 'recast_medium'
                'Low' = 'recast_low'
                'Info' = 'recast_info'
                'Exclude' = 'exclude'
            }
            
            $strType = $dicType[$Type]
            
            $pRulehash = @{
                'plugin_id' = $PluginId
                'host' = $ComputerName
                'type' = $strType
                'date' = $dtExpiration
            }
            
            $pRuleJson = ConvertTo-Json -InputObject $pRulehash -Compress

            InvokeNessusRestRequest -SessionObject $Connection -Path '/plugin-rules' -Method 'Post' `
            -Parameter $pRuleJson -ContentType 'application/json'
        }
    }
    
    End
    {
    
    }
}


function Remove-NessusPluginRule
{
    <#
            .SYNOPSIS
            Removes a Nessus plugin rule

            .DESCRIPTION
            Can be used to clear a previously defined, scan report altering rule

            .PARAMETER SessionId
            ID of a valid Nessus session

            .PARAMETER Id
            ID number of the rule which would you like removed/deleted

            .EXAMPLE
            Remove-NessusPluginRule -SessionId 0 -Id 500
            Will delete a plugin rule with an ID of 500

            .EXAMPLE
            Get-NessusPluginRule -SessionId 0 | Remove-NessusPluginRule
            Will delete all rules

            .EXAMPLE
            Get-NessusPluginRule -SessionId 0 | ? {$_.Host -eq 'myComputer'} | Remove-NessusPluginRule
            Will find all plugin rules that match the computer name, and delete them

            .INPUTS
            Can accept pipeline data from Get-NessusPluginRule 

            .OUTPUTS
            Empty, unless an error is received from the server
    #>


    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true, Position=0,
        ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32]
        $SessionId,
        
        [Parameter(Mandatory=$true, Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int32]
        $Id
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
            InvokeNessusRestRequest -SessionObject $Connection -Path ('/plugin-rules/{0}' -f $Id) -Method 'Delete'
        }
    }
    
    End
    {
    
    }
}


function Edit-NessusPluginRule
{
    <#
            .SYNOPSIS
            Edits a Nessus plugin rule

            .DESCRIPTION
            Can be used to change a previously defined, scan report altering rule

            .PARAMETER SessionId
            ID of a valid Nessus session

            .PARAMETER Id
            ID number of the rule which would you like removed/deleted

            .PARAMETER PluginId
            ID number of the plugin which would you like altered

            .PARAMETER ComputerName
            Name, IP address, or Wildcard (*), which defines the the host(s) affected by the rule

            .PARAMETER Type
            Severity level you would like future scan reports to display for the defined host(s)

            .PARAMETER Expiration
            Date/Time object, which defines the time you would like the rule to expire. Not required
            
            .EXAMPLE
            Edit-NessusPluginRule -SessionId 0 -Id 500 -ComputerName 'YourComputer' -Expiration (([datetime]::Now).AddDays(10)) -Type Low
            Will edit a plugin rule with an ID of 500, to have a new computer name. Rule expires in 10 days

            .EXAMPLE
            Get-NessusPluginRule -SessionId 0 | Edit-NessusPluginRule -Type High
            Will alter all rules to now have a serverity of 'Info'

            .EXAMPLE
            Get-NessusPluginRule -SessionId 0 | ? {$_.Host -eq 'myComputer'} | Edit-NessusPluginRule -Type 'High'
            Will find all plugin rules that match the computer name, and set their severity to high

            .INPUTS
            Can accept pipeline data from Get-NessusPluginRule 

            .OUTPUTS
            Empty, unless an error is received from the server
    #>


    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true, Position=0,
        ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32]
        $SessionId,
        
        [Parameter(Mandatory=$true, Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int32]
        $Id,
        
        [Parameter(Mandatory=$true, Position=2,
        ValueFromPipelineByPropertyName=$true)]
        [int32]
        $PluginId,
        
        [Parameter(Mandatory=$false, Position=3,
        ValueFromPipelineByPropertyName=$true)]
        [Alias('IPAddress','IP','Host')]
        [String]
        $ComputerName = '*',
        
        [Parameter(Mandatory=$true, Position=4, 
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Critical','High','Medium','Low','Info','Exclude')]
        [String]
        $Type,
        
        [Parameter(Mandatory=$false, Position=5, 
        ValueFromPipelineByPropertyName=$true)]
        [datetime] 
        $Expiration
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
        
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    }
    
    Process
    {
        foreach($Connection in $ToProcess)
        {
            $dtExpiration = $null
                    
            If ($Expiration)
            {
                
                $dtExpiration = (New-TimeSpan -Start $origin -End $Expiration).TotalSeconds.ToInt32($null)
            }
                    
            $dicType = @{
                'Critical' = 'recast_critical'
                'High' = 'recast_high'
                'Medium' = 'recast_medium'
                'Low' = 'recast_low'
                'Info' = 'recast_info'
                'Exclude' = 'exclude'
            }
            
            $strType = $dicType[$Type]
            
            $pRulehash = @{
                'plugin_id' = $PluginId
                'host' = $ComputerName
                'type' = $strType
                'date' = $dtExpiration
            }
            
            $pRuleJson = ConvertTo-Json -InputObject $pRulehash -Compress

            InvokeNessusRestRequest -SessionObject $Connection -Path ('/plugin-rules/{0}' -f $Id) -Method 'Put' `
            -Parameter $pRuleJson -ContentType 'application/json'
        }
    }
    
    End
    {
    
    }
}
