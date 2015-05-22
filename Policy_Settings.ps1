<#
.Synopsis
   Get the configured port range set on a policy for discovery.
.DESCRIPTION
   Get the configured port range set on a policy for discovery.
.EXAMPLE
   Get-NessusPolicyPortRange -SessionId 0 -PolicyId 112 | fl 


    PolicyId  : 112
    PortRange : default
#>
function Get-NessusPolicyPortRange
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
        [int32]
        $SessionId,

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32[]]
        $PolicyId
    )

    Begin
    {
        $sessions = Get-NessusSession | Select-Object -ExpandProperty sessionid
        if ($SessionId -notin $sessions)
        {
            throw "SessionId $($SessionId) is not present in the current sessions."
        }
        $Session = Get-NessusSession -SessionId $SessionId
    }
    Process
    {
        foreach ($PolicyToChange in $PolicyId)
        {
            try
            {
                $Policy = Get-NessusPolicyDetail -SessionId $Session.SessionId -PolicyId $PolicyToChange
                $UpdateProps = [ordered]@{
                    'PolicyId' = $PolicyToChange
                    'PortRange' = $Policy.settings.portscan_range
                }
                $PolSettingsObj = [PSCustomObject]$UpdateProps
                $PolSettingsObj.pstypenames.insert(0,'Nessus.PolicySetting')
                $PolSettingsObj
            }
            catch
            {
                throw $_
            }

        }
    }
    End
    {
    }
}

<#
.Synopsis
   Set port range set on a Policy for discovery.
.DESCRIPTION
   Set port range set on a Policy for discovery.
.EXAMPLE
   Set-NessusPolicyPortRange -SessionId 0 -PolicyId 112 -Port 22,23,25,80,400-1000 | fl

    PolicyId  : 112
    PortRange : 22,23,25,80,400-1000
#>
function Set-NessusPolicyPortRange
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
        [int32]
        $SessionId,

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32[]]
        $PolicyId,

        [Parameter(Mandatory=$true,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [string[]]
        $Port
    )

    Begin
    {
        $sessions = Get-NessusSession | Select-Object -ExpandProperty sessionid
        if ($SessionId -notin $sessions)
        {
            throw "SessionId $($SessionId) is not present in the current sessions."
        }
        $Session = Get-NessusSession -SessionId $SessionId
    }
    Process
    {
        foreach ($PolicyToChange in $PolicyId)
        {
            $RequestParams = @{
                'SessionObject' = $Session
                'Path' = "/policies/$($PolicyToChange)"
                'Method' = 'PUT'
                'ContentType' = 'application/json'
                'Parameter'= "{`"settings`": {`"portscan_range`": `"$($Port -join ",")`"}}"
            }

            InvokeNessusRestRequest @RequestParams | Out-Null
            Get-NessusPolicyPortRange -SessionId $SessionId -PolicyId $PolicyToChange

        }
    }
    End
    {
    }
}

<#
.Synopsis
   Adds to the currently configured configured port range set on a policy for discovery.
.DESCRIPTION
   Adds to the currently configured configured port range set on a policy for discovery.
.EXAMPLE
   Add-NessusPolicyPortRange -SessionId 0 -PolicyId 112 -Port 3389 | fl

    PolicyId  : 112
    PortRange : 22,23,25,80,400-1000,3389
#>
function Add-NessusPolicyPortRange
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
        [int32]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32[]]
        $PolicyId,

        [Parameter(Mandatory=$true,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [string[]]
        $Port
    )

    Begin
    {
        $sessions = Get-NessusSession | Select-Object -ExpandProperty sessionid
        if ($SessionId -notin $sessions)
        {
            throw "SessionId $($SessionId) is not present in the current sessions."
        }
        $Session = Get-NessusSession -SessionId $SessionId
    }
    Process
    {
        foreach ($PolicyToChange in $PolicyId)
        {
            try{
                $Policy = Get-NessusPolicyDetail -SessionId $Session.SessionId -PolicyId $PolicyToChange
                $Ports = "$($Policy.settings.portscan_range),$($Port -join ",")"
                $RequestParams = @{
                    'SessionObject' = $Session
                    'Path' = "/policies/$($PolicyToChange)"
                    'Method' = 'PUT'
                    'ContentType' = 'application/json'
                    'Parameter'= "{`"settings`": {`"portscan_range`": `"$($Ports)`"}}"
                }

                InvokeNessusRestRequest @RequestParams | Out-Null
                Get-NessusPolicyPortRange -SessionId $SessionId -PolicyId $PolicyToChange
             }
             catch
             {
               throw $_
             }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Get the configuration state of the port scanner in a policy.
.DESCRIPTION
   Get the configuration state of the port scanner in a policy.
.EXAMPLE
   Get-NessusPolicyPortScanner -SessionId 0 -PolicyId 111 | fl 


    PolicyId   : 111
    SYNScanner : yes
    UDPScanner : no
    TCPScanner : yes
#>
function Get-NessusPolicyPortScanner
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
        [int32]
        $SessionId,

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32[]]
        $PolicyId
    )

    Begin
    {
        $sessions = Get-NessusSession | Select-Object -ExpandProperty sessionid
        if ($SessionId -notin $sessions)
        {
            throw "SessionId $($SessionId) is not present in the current sessions."
        }
        $Session = Get-NessusSession -SessionId $SessionId
    }
    Process
    {
        foreach ($PolicyToChange in $PolicyId)
        {
            try
            {
                $Policy = Get-NessusPolicyDetail -SessionId $Session.SessionId -PolicyId $PolicyToChange
                $UpdateProps = [ordered]@{
                    'PolicyId' = $PolicyToChange
                    'SYNScanner' = $Policy.settings.syn_scanner
                    'UDPScanner' = $Policy.settings.udp_scanner
                    'TCPScanner' = $Policy.settings.tcp_scanner
                }
                $PolSettingsObj = [PSCustomObject]$UpdateProps
                $PolSettingsObj.pstypenames.insert(0,'Nessus.PolicySetting')
                $PolSettingsObj
            }
            catch
            {
                throw $_
            }

        }
    }
    End
    {
    }
}

<#
.Synopsis
   Enable one or more port scanners on a policy.
.DESCRIPTION
   Enable one or more port scanners on a policy.
.EXAMPLE
   Enable-NessusPolicyPortScanner -SessionId 0 -PolicyId 111 -ScanMethods SYN,TCP | fl


    PolicyId   : 111
    SYNScanner : yes
    UDPScanner : no
    TCPScanner : yes
#>
function Enable-NessusPolicyPortScanner
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory = $true,
                   Position = 0,
                   ValueFromPipelineByPropertyName = $true)]
        [Alias('Index')]
        [int32]
        $SessionId,

        [Parameter(Mandatory = $true,
                   Position = 1,
                   ValueFromPipelineByPropertyName = $true)]
        [int32[]]
        $PolicyId,

        [Parameter(Mandatory = $true,
                   Position = 2,
                   ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('TCP', 'SYN', 'UDP')]
        [string[]]
        $ScanMethods
    )

    Begin
    {
        $sessions = Get-NessusSession | Select-Object -ExpandProperty sessionid
        if ($SessionId -notin $sessions)
        {
            throw "SessionId $($SessionId) is not present in the current sessions."
        }
        $Session = Get-NessusSession -SessionId $SessionId

        $Scanners = @{}
        foreach ($Scanner in $ScanMethods)
        {
            if($Scanner -eq 'TCP')
            {$Scanners['tcp_scanner'] = 'yes'}

            if($Scanner -eq 'UDP')
            {$Scanners['udp_scanner'] = 'yes'}

            if($Scanner -eq 'SYN')
            {$Scanners['syn_scanner'] = 'yes'}
        }

        $Settings = @{'settings' = $Scanners}
        $SettingsJson = ConvertTo-Json -InputObject $Settings -Compress
    }
    Process
    {
        foreach ($PolicyToChange in $PolicyId)
        {
            $RequestParams = @{
                'SessionObject' = $Session
                'Path' = "/policies/$($PolicyToChange)"
                'Method' = 'PUT'
                'ContentType' = 'application/json'
                'Parameter'= $SettingsJson
            }

            InvokeNessusRestRequest @RequestParams | Out-Null
            Get-NessusPolicyPortScanner -SessionId $SessionId -PolicyId $PolicyToChange

        }
    }
    End
    {
    }
}


<#
.Synopsis
   Disable one or more port scanners on a policy.
.DESCRIPTION
   Disable one or more port scanners on a policy.
.EXAMPLE
   Disable-NessusPolicyPortScanner -SessionId 0 -PolicyId 111 -ScanMethods UDP | fl


    PolicyId   : 111
    SYNScanner : yes
    UDPScanner : no
    TCPScanner : yes
#>
function Disable-NessusPolicyPortScanner
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory = $true,
                   Position = 0,
                   ValueFromPipelineByPropertyName = $true)]
        [Alias('Index')]
        [int32]
        $SessionId,

        [Parameter(Mandatory = $true,
                   Position = 1,
                   ValueFromPipelineByPropertyName = $true)]
        [int32[]]
        $PolicyId,

        [Parameter(Mandatory = $true,
                   Position = 2,
                   ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('TCP', 'SYN', 'UDP')]
        [string[]]
        $ScanMethods
    )

    Begin
    {
        $sessions = Get-NessusSession | Select-Object -ExpandProperty sessionid
        if ($SessionId -notin $sessions)
        {
            throw "SessionId $($SessionId) is not present in the current sessions."
        }
        $Session = Get-NessusSession -SessionId $SessionId

        $Scanners = @{}
        foreach ($Scanner in $ScanMethods)
        {
            if($Scanner -eq 'TCP')
            {$Scanners['tcp_scanner'] = 'no'}

            if($Scanner -eq 'UDP')
            {$Scanners['udp_scanner'] = 'no'}

            if($Scanner -eq 'SYN')
            {$Scanners['syn_scanner'] = 'no'}
        }

        $Settings = @{'settings' = $Scanners}
        $SettingsJson = ConvertTo-Json -InputObject $Settings -Compress
    }
    Process
    {
        foreach ($PolicyToChange in $PolicyId)
        {
            $RequestParams = @{
                'SessionObject' = $Session
                'Path' = "/policies/$($PolicyToChange)"
                'Method' = 'PUT'
                'ContentType' = 'application/json'
                'Parameter'= $SettingsJson
            }

            InvokeNessusRestRequest @RequestParams | Out-Null
            Get-NessusPolicyPortScanner -SessionId $SessionId -PolicyId $PolicyToChange

        }
    }
    End
    {
    }
}


<#
.Synopsis
   Get the local port enumeration settings for a policy.
.DESCRIPTION
   Get the local port enumeration settings for a policy. On Windows system Nessus uses
   WMI to run and parse netstat information, on Linux and Unix host it uses SSH to run
   and parse the netstat information. SNMP Can also be used to query the open port MIBs
   for the different operating systems to avoid scanning the host.
.EXAMPLE
   Get-NessusPolicyLocalPortEnumeration -SessionId 0 -PolicyId 111


    PolicyId             : 111
    WMINetstat           : yes
    SSHNetstat           : yes
    SNMPScanner          : no
    VerifyOpenPorts      : yes
    ScanOnlyIfLocalFails : no
#>
function Get-NessusPolicyLocalPortEnumeration
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
        [int32]
        $SessionId,

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32[]]
        $PolicyId
    )

    Begin
    {
        $sessions = Get-NessusSession | Select-Object -ExpandProperty sessionid
        if ($SessionId -notin $sessions)
        {
            throw "SessionId $($SessionId) is not present in the current sessions."
        }
        $Session = Get-NessusSession -SessionId $SessionId
    }
    Process
    {
        foreach ($PolicyToChange in $PolicyId)
        {
            try
            {
                $Policy = Get-NessusPolicyDetail -SessionId $Session.SessionId -PolicyId $PolicyToChange
                $UpdateProps = [ordered]@{
                    'PolicyId' = $PolicyToChange
                    'WMINetstat' = $Policy.settings.wmi_netstat_scanner
                    'SSHNetstat' = $Policy.settings.ssh_netstat_scanner
                    'SNMPScanner' = $Policy.settings.snmp_scanner
                    'VerifyOpenPorts' = $Policy.settings.verify_open_ports
                    'ScanOnlyIfLocalFails' = $Policy.settings.only_portscan_if_enum_failed
                }
                $PolSettingsObj = [PSCustomObject]$UpdateProps
                $PolSettingsObj.pstypenames.insert(0,'Nessus.PolicySetting')
                $PolSettingsObj
            }
            catch
            {
                throw $_
            }

        }
    }
    End
    {
    }
}

<#
.Synopsis
   Enable the local port enumeration settings for a policy.
.DESCRIPTION
   Enable local port enumeration settings for a policy. On Windows system Nessus uses
   WMI to run and parse netstat information, on Linux and Unix host it uses SSH to run
   and parse the netstat information. SNMP Can also be used to query the open port MIBs
   for the different operating systems to avoid scanning the host.
.EXAMPLE
   Enable-NessusPolicyLocalPortEnumeration -SessionId 0 -PolicyId 111 -ScanMethods WMINetstat,SNMPScanner,SSHNetstat -VerifyOpenPorts -ScanOnlyIfLocalFails


    PolicyId             : 111
    WMINetstat           : yes
    SSHNetstat           : yes
    SNMPScanner          : yes
    VerifyOpenPorts      : yes
    ScanOnlyIfLocalFails : yes
#>
function Enable-NessusPolicyLocalPortEnumeration
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory = $true,
                   Position = 0,
                   ValueFromPipelineByPropertyName = $true)]
        [Alias('Index')]
        [int32]
        $SessionId,

        [Parameter(Mandatory = $true,
                   Position = 1,
                   ValueFromPipelineByPropertyName = $true)]
        [int32[]]
        $PolicyId,

        [Parameter(Mandatory = $true,
                   Position = 2,
                   ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('WMINetstat', 'SSHNetstat', 'SNMPScanner')]
        [string[]]
        $ScanMethods,

        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [switch]
        $VerifyOpenPorts,

        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [switch]
        $ScanOnlyIfLocalFails
    )

    Begin
    {
        $sessions = Get-NessusSession | Select-Object -ExpandProperty sessionid
        if ($SessionId -notin $sessions)
        {
            throw "SessionId $($SessionId) is not present in the current sessions."
        }
        $Session = Get-NessusSession -SessionId $SessionId

        $Scanners = @{}
        foreach ($Scanner in $ScanMethods)
        {
            if($Scanner -eq 'WMINetstat')
            {$Scanners['wmi_netstat_scanner'] = 'yes'}

            if($Scanner -eq 'SSHNetstat')
            {$Scanners['ssh_netstat_scanner'] = 'yes'}

            if($Scanner -eq 'SNMPScanner')
            {$Scanners['snmp_scanner'] = 'yes'}
        }

        if($VerifyOpenPorts)
        {$Scanners['verify_open_ports'] = 'yes'}

        if($ScanOnlyIfLocalFails)
        {$Scanners['only_portscan_if_enum_failed'] = 'yes'}

        $Settings = @{'settings' = $Scanners}
        $SettingsJson = ConvertTo-Json -InputObject $Settings -Compress
    }
    Process
    {
        foreach ($PolicyToChange in $PolicyId)
        {
            $RequestParams = @{
                'SessionObject' = $Session
                'Path' = "/policies/$($PolicyToChange)"
                'Method' = 'PUT'
                'ContentType' = 'application/json'
                'Parameter'= $SettingsJson
            }

            InvokeNessusRestRequest @RequestParams | Out-Null
            Get-NessusPolicyLocalPortEnumeration -SessionId $SessionId -PolicyId $PolicyToChange

        }
    }
    End
    {
    }
}

<#
.Synopsis
   Disable the local port enumeration settings for a policy.
.DESCRIPTION
   Disable local port enumeration settings for a policy. On Windows system Nessus uses
   WMI to run and parse netstat information, on Linux and Unix host it uses SSH to run
   and parse the netstat information. SNMP Can also be used to query the open port MIBs
   for the different operating systems to avoid scanning the host.
.EXAMPLE
   Disable-NessusPolicyLocalPortEnumeration -SessionId 0 -PolicyId 111 -ScanMethods SNMPScanner -ScanOnlyIfLocalFails


    PolicyId             : 111
    WMINetstat           : yes
    SSHNetstat           : yes
    SNMPScanner          : no
    VerifyOpenPorts      : yes
    ScanOnlyIfLocalFails : no
#>
function Disable-NessusPolicyLocalPortEnumeration
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory = $true,
                   Position = 0,
                   ValueFromPipelineByPropertyName = $true)]
        [Alias('Index')]
        [int32]
        $SessionId,

        [Parameter(Mandatory = $true,
                   Position = 1,
                   ValueFromPipelineByPropertyName = $true)]
        [int32[]]
        $PolicyId,

        [Parameter(Mandatory = $true,
                   Position = 2,
                   ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('WMINetstat', 'SSHNetstat', 'SNMPScanner')]
        [string[]]
        $ScanMethods,

        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [switch]
        $VerifyOpenPorts,

        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [switch]
        $ScanOnlyIfLocalFails
    )

    Begin
    {
        $sessions = Get-NessusSession | Select-Object -ExpandProperty sessionid
        if ($SessionId -notin $sessions)
        {
            throw "SessionId $($SessionId) is not present in the current sessions."
        }
        $Session = Get-NessusSession -SessionId $SessionId

        $Scanners = @{}
        foreach ($Scanner in $ScanMethods)
        {
            if($Scanner -eq 'WMINetstat')
            {$Scanners['wmi_netstat_scanner'] = 'no'}

            if($Scanner -eq 'SSHNetstat')
            {$Scanners['ssh_netstat_scanner'] = 'no'}

            if($Scanner -eq 'SNMPScanner')
            {$Scanners['snmp_scanner'] = 'no'}
        }

        if($VerifyOpenPorts)
        {$Scanners['verify_open_ports'] = 'no'}

        if($ScanOnlyIfLocalFails)
        {$Scanners['only_portscan_if_enum_failed'] = 'no'}

        $Settings = @{'settings' = $Scanners}
        $SettingsJson = ConvertTo-Json -InputObject $Settings -Compress
    }
    Process
    {
        foreach ($PolicyToChange in $PolicyId)
        {
            $RequestParams = @{
                'SessionObject' = $Session
                'Path' = "/policies/$($PolicyToChange)"
                'Method' = 'PUT'
                'ContentType' = 'application/json'
                'Parameter'= $SettingsJson
            }

            InvokeNessusRestRequest @RequestParams | Out-Null
            Get-NessusPolicyLocalPortEnumeration -SessionId $SessionId -PolicyId $PolicyToChange

        }
    }
    End
    {
    }
}