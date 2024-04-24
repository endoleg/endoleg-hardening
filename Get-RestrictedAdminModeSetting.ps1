#Get-RestrictedAdminModeSetting
    $Path = 'HKLM:SYSTEM\CurrentControlSet\Control\Lsa'
        $RAM = (Get-ItemProperty -Path $Path).DisableRestrictedAdmin
        $Creds = (Get-ItemProperty -Path $Path).DisableRestrictedAdminOutboundCreds
        if ($RAM -eq '0' -and $Creds -eq '1'){
            return $true
        } else {
            return $false
        }
