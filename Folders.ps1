#region Folders
####################################################################

<#
.Synopsis
   Gets folders configured on a Nessus Server.
.DESCRIPTION
   Gets folders configured on a Nessus Server.
.EXAMPLE
    Get-NessusFolder 0

    Name    : My Scans
    Id      : 2
    Type    : main
    Default : 1
    Unread  : 5

    Name    : Trash
    Id      : 3
    Type    : trash
    Default : 0
    Unread  : 

    Name    : Test Folder 2
    Id      : 10
    Type    : custom
    Default : 0
    Unread  : 0
#>
function Get-NessusFolder
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
            $Folders =  InvokeNessusRestRequest -SessionObject $Connection -Path '/folders' -Method 'Get'

            if ($Folders -is [psobject])
            {
                foreach ($folder in $Folders.folders)
                {
                    $FolderProps = [ordered]@{}
                    $FolderProps.Add('Name', $folder.name)
                    $FolderProps.Add('Id', $folder.id)
                    $FolderProps.Add('Type', $folder.type)
                    $FolderProps.Add('Default', $folder.default_tag)
                    $FolderProps.Add('Unread', $folder.unread_count)
                    $FolderObj = New-Object -TypeName psobject -Property $FolderProps
                    $FolderObj.pstypenames[0] = 'Nessus.Folder'
                    $FolderObj
                }
            }
        }
    }
    End
    {
    }
}

#endregion