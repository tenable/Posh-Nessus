
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
        
        [Parameter(Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int32]
        $PluginId

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
                    
                    $objPluginDetails = Show-NessusPlugin -SessionId $SessionId -PluginId $pRule.plugin_id
                    
                    $pRuleProps = [Ordered]@{}
                    $pRuleProps.add('ID', $pRule.id)
                    $pRuleProps.add('Host', $pRule.host)
                    $pRuleProps.add('Plugin_ID', $pRule.plugin_id)
                    $pRuleProps.add('Plugin', $objPluginDetails.Name)
                    $pRuleProps.add('Expiration', $dtExpiration)
                    $pRuleProps.add('Type', $pRule.type)
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

