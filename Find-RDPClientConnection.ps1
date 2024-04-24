
Function Find-RDPClientConnection
{
<#
.SYNOPSIS

Search the registry to find saved RDP client connections. This shows you what connections an RDP client has remembered, indicating what servers the user
usually RDP's to.

Function: Find-RDPClientConnection  
Author: Joe Bialek, Twitter: @JosephBialek  
Required Dependencies: None  
Optional Dependencies: None  

.DESCRIPTION

Search the registry to find saved RDP client connections. This shows you what connections an RDP client has remembered, indicating what servers the user usually RDP's to.

.EXAMPLE

Find-RDPClientConnection
Find unique saved RDP client connections.

.NOTES

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
#>
    $ReturnInfo = @{}

    New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null

    #Attempt to enumerate the servers for all users
    $Users = Get-ChildItem -Path "HKU:\"
    foreach ($UserSid in $Users.PSChildName)
    {
        $Servers = Get-ChildItem "HKU:\$($UserSid)\Software\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue

        foreach ($Server in $Servers)
        {
            $Server = $Server.PSChildName
            $UsernameHint = (Get-ItemProperty -Path "HKU:\$($UserSid)\Software\Microsoft\Terminal Server Client\Servers\$($Server)").UsernameHint

            $Key = $UserSid + "::::" + $Server + "::::" + $UsernameHint

            if (!$ReturnInfo.ContainsKey($Key))
            {
                $SIDObj = New-Object System.Security.Principal.SecurityIdentifier($UserSid)
                $User = ($SIDObj.Translate([System.Security.Principal.NTAccount])).Value

                $Properties = @{
                    CurrentUser = $User
                    Server = $Server
                    UsernameHint = $UsernameHint
                }

                $Item = New-Object PSObject -Property $Properties
                $ReturnInfo.Add($Key, $Item)
            }
        }
    }

    return $ReturnInfo
}
Find-RDPClientConnection
