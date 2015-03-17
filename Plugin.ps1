
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
                        $Attributes.add("$($Attribute.attribute_name)", "$($Attribute.attribute_value)")
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
                $DetailProps.Add('Id', $FamilyDetails.id)
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
