#region Server
####################################################################

<#
.Synopsis
   Get information on a Nessus Server for a given session.
.DESCRIPTION
   Get information on a Nessus Server for a given session.
.EXAMPLE
    Get-NessusServerInfo -SessionId 0 -Verbose
    VERBOSE: GET https://192.168.1.205:8834/server/properties with 0-byte payload
    VERBOSE: received 478-byte response of content type application/json


    loaded_plugin_set : 201502021615
    server_uuid       : 9b7b6864-d654-345f-57f2-aeaa5438654421ba99bb9f34e2b5
    update            : @{href=; new_version=0; restart=0}
    expiration        : 1505793600
    nessus_ui_version : 6.0.2
    nessus_type       : Nessus
    notifications     : {}
    expiration_time   : 959
    capabilities      : @{multi_scanner=True; report_email_config=False}
    plugin_set        : 201502021615
    idle_timeout      : 
    scanner_boottime  : 1422920519
    login_banner      : 
    server_version    : 6.0.2
    feed              : ProFeed
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
        [int32[]]$SessionId = @()
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
                
            $ServerInfo = InvokeNessusRestRequest -SessionObject $Connection -Path '/server/properties' -Method 'Get'
                 
            if ($ServerInfo -is [psobject])
            {
                $SrvInfoProp = [ordered]@{}
                $SrvInfoProp.Add('NessusType', $ServerInfo.nessus_type)
                $SrvInfoProp.Add('ServerVersion', $ServerInfo.server_version)
                $SrvInfoProp.Add('UIVersion', $ServerInfo.nessus_ui_version)
                $SrvInfoProp.Add('PluginSet', $ServerInfo.loaded_plugin_set)
                $SrvInfoProp.Add('Feed', $ServerInfo.feed)
                $SrvInfoProp.Add('FeedExpiration', $origin.AddSeconds($ServerInfo.expiration).ToLocalTime())
                $SrvInfoProp.Add('Capabilities', $ServerInfo.capabilities)
                $SrvInfoProp.Add('UUID', $ServerInfo.server_uuid)
                $SrvInfoProp.Add('Update', $ServerInfo.update)
                $SrvInfoObj = New-Object -TypeName psobject -Property $SrvInfoProp
                $SrvInfoObj.pstypenames[0] = 'Nessus.ServerInfo'
                $SrvInfoObj
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Get the current status of the Nessus Server for a session.
.DESCRIPTION
   Get the current status of the Nessus Server for a session.
.EXAMPLE
   Get-NessusServerStatus -Id 0


    Progress : 
    Status   : ready
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
                
            $ServerStatus = InvokeNessusRestRequest -SessionObject $Connection -Path '/server/status' -Method 'Get'
                 
            if ($ServerStatus -is [psobject])
            {
                $ServerStatus.pstypenames[0] = 'Nessus.ServerStatus'
                $ServerStatus
            }
        }
    }
    End
    {
    }
}

#endregion