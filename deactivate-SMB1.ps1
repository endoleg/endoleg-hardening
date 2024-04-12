<#
#activate audit 
if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -force -ea SilentlyContinue };
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AuditSmb1Access' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;

#audit
Write-Output ""
    write-verbose -message "----------- get-smbshare Shares Start (Fehlermeldungen normal) -------------------------------------" -verbose
        $smbshare=get-smbshare
        $smbshare
    write-verbose -message "----------- Get-SmbConnection mit Write-Verbose -Verbose-------------------------------------" -verbose
        Get-SmbConnection | select Servername, ShareName, UserName, Credential, Dialect, NumOpens | Write-Verbose -Verbose

    write-verbose -message "----------- Get-SmbServerConfiguration -------------------------------------" -verbose
        Get-SmbServerConfiguration | out-file -filepath C:\Get-SmbServerConfiguration.txt -Force
        Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
        Get-SmbServerConfiguration | Select-Object EnableSMB2Protocol

    Write-Verbose -Message "----------- Get-WindowsOptionalFeature -Online -FeatureName smb1protocol----------------" -Verbose
    Get-WindowsOptionalFeature -Online -FeatureName smb1protocol
    #Enable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart

#Disable SMB 1.0 
#run the following command
Get-SmbServerConfiguration | Select enableSMB1Protocol
Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force
Get-SmbServerConfiguration | Select enableSMB1Protocol
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart

#or
Uninstall-WindowsFeature -Name FS-SMB1

US-CERT: Blocking SMB von 2017:
https://www.cisa.gov/uscert/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices



nmap-check
How to get to list of the supported protocols and dialects of a SMB server with nmap

nmap -p445 --script smb-protocols <targetIP>
nmap -p139 --script smb-protocols <targetIP>

Bonus: You can use parameter -d to debug

Download nmap
https://nmap.org/download.html

How to Scan for SMB Vulnerabilities with Nmap
https://www.itms-us.com/Tips-And-Tricks/Scan-For-SMB-Vulnerabilities

#>

function Get-ComputerSMB {
    <#
    .SYNOPSIS
    Short description

    .DESCRIPTION
    Long description

    .PARAMETER ComputerName
    Parameter description

    .EXAMPLE
    Get-ComputerSMB -ComputerName $ENV:COMPUTERNAME

    .NOTES
    General notes
    #>

    [CmdletBinding()]
    param(
        [string[]] $ComputerName
    )

    [Array] $CollectionComputers = $ComputerName.Where( { $_ -eq $Env:COMPUTERNAME }, 'Split')
    $SMB = @(
        if ($CollectionComputers[0].Count -gt 0) {
            $Output = Get-SmbServerConfiguration
            foreach ($_ in $Output) {
                [PSCustomObject] @{
                    ComputerName                    = $Env:COMPUTERNAME
                    AnnounceComment                 = $_.AnnounceComment
                    AnnounceServer                  = $_.AnnounceServer
                    AsynchronousCredits             = $_.AsynchronousCredits
                    AuditSmb1Access                 = $_.AuditSmb1Access
                    AutoDisconnectTimeout           = $_.AutoDisconnectTimeout
                    AutoShareServer                 = $_.AutoShareServer
                    AutoShareWorkstation            = $_.AutoShareWorkstation
                    CachedOpenLimit                 = $_.CachedOpenLimit
                    DurableHandleV2TimeoutInSeconds = $_.DurableHandleV2TimeoutInSeconds
                    EnableAuthenticateUserSharing   = $_.EnableAuthenticateUserSharing
                    EnableDownlevelTimewarp         = $_.EnableDownlevelTimewarp
                    EnableForcedLogoff              = $_.EnableForcedLogoff
                    EnableLeasing                   = $_.EnableLeasing
                    EnableMultiChannel              = $_.EnableMultiChannel
                    EnableOplocks                   = $_.EnableOplocks
                    EnableSecuritySignature         = $_.EnableSecuritySignature
                    EnableSMB1Protocol              = $_.EnableSMB1Protocol
                    EnableSMB2Protocol              = $_.EnableSMB2Protocol
                    EnableStrictNameChecking        = $_.EnableStrictNameChecking
                    EncryptData                     = $_.EncryptData
                    IrpStackSize                    = $_.IrpStackSize
                    KeepAliveTime                   = $_.KeepAliveTime
                    MaxChannelPerSession            = $_.MaxChannelPerSession
                    MaxMpxCount                     = $_.MaxMpxCount
                    MaxSessionPerConnection         = $_.MaxSessionPerConnection
                    MaxThreadsPerQueue              = $_.MaxThreadsPerQueue
                    MaxWorkItems                    = $_.MaxWorkItems
                    NullSessionPipes                = $_.NullSessionPipes
                    NullSessionShares               = $_.NullSessionShares
                    OplockBreakWait                 = $_.OplockBreakWait
                    PendingClientTimeoutInSeconds   = $_.PendingClientTimeoutInSeconds
                    RejectUnencryptedAccess         = $_.RejectUnencryptedAccess
                    RequireSecuritySignature        = $_.RequireSecuritySignature
                    ServerHidden                    = $_.ServerHidden
                    Smb2CreditsMax                  = $_.Smb2CreditsMax
                    Smb2CreditsMin                  = $_.Smb2CreditsMin
                    SmbServerNameHardeningLevel     = $_.SmbServerNameHardeningLevel
                    TreatHostAsStableStorage        = $_.TreatHostAsStableStorage
                    ValidateAliasNotCircular        = $_.ValidateAliasNotCircular
                    ValidateShareScope              = $_.ValidateShareScope
                    ValidateShareScopeNotAliased    = $_.ValidateShareScopeNotAliased
                    ValidateTargetName              = $_.ValidateTargetName
                }
            }
        }
        if ($CollectionComputers[1].Count -gt 0) {
            $Output = Get-SmbServerConfiguration -CimSession $CollectionComputers[1]
            foreach ($_ in $Output) {
                [PSCustomObject] @{
                    ComputerName                    = $_.PSComputerName
                    AnnounceComment                 = $_.AnnounceComment
                    AnnounceServer                  = $_.AnnounceServer
                    AsynchronousCredits             = $_.AsynchronousCredits
                    AuditSmb1Access                 = $_.AuditSmb1Access
                    AutoDisconnectTimeout           = $_.AutoDisconnectTimeout
                    AutoShareServer                 = $_.AutoShareServer
                    AutoShareWorkstation            = $_.AutoShareWorkstation
                    CachedOpenLimit                 = $_.CachedOpenLimit
                    DurableHandleV2TimeoutInSeconds = $_.DurableHandleV2TimeoutInSeconds
                    EnableAuthenticateUserSharing   = $_.EnableAuthenticateUserSharing
                    EnableDownlevelTimewarp         = $_.EnableDownlevelTimewarp
                    EnableForcedLogoff              = $_.EnableForcedLogoff
                    EnableLeasing                   = $_.EnableLeasing
                    EnableMultiChannel              = $_.EnableMultiChannel
                    EnableOplocks                   = $_.EnableOplocks
                    EnableSecuritySignature         = $_.EnableSecuritySignature
                    EnableSMB1Protocol              = $_.EnableSMB1Protocol
                    EnableSMB2Protocol              = $_.EnableSMB2Protocol
                    EnableStrictNameChecking        = $_.EnableStrictNameChecking
                    EncryptData                     = $_.EncryptData
                    IrpStackSize                    = $_.IrpStackSize
                    KeepAliveTime                   = $_.KeepAliveTime
                    MaxChannelPerSession            = $_.MaxChannelPerSession
                    MaxMpxCount                     = $_.MaxMpxCount
                    MaxSessionPerConnection         = $_.MaxSessionPerConnection
                    MaxThreadsPerQueue              = $_.MaxThreadsPerQueue
                    MaxWorkItems                    = $_.MaxWorkItems
                    NullSessionPipes                = $_.NullSessionPipes
                    NullSessionShares               = $_.NullSessionShares
                    OplockBreakWait                 = $_.OplockBreakWait
                    PendingClientTimeoutInSeconds   = $_.PendingClientTimeoutInSeconds
                    RejectUnencryptedAccess         = $_.RejectUnencryptedAccess
                    RequireSecuritySignature        = $_.RequireSecuritySignature
                    ServerHidden                    = $_.ServerHidden
                    Smb2CreditsMax                  = $_.Smb2CreditsMax
                    Smb2CreditsMin                  = $_.Smb2CreditsMin
                    SmbServerNameHardeningLevel     = $_.SmbServerNameHardeningLevel
                    TreatHostAsStableStorage        = $_.TreatHostAsStableStorage
                    ValidateAliasNotCircular        = $_.ValidateAliasNotCircular
                    ValidateShareScope              = $_.ValidateShareScope
                    ValidateShareScopeNotAliased    = $_.ValidateShareScopeNotAliased
                    ValidateTargetName              = $_.ValidateTargetName
                }
            }
        }
    )
    $SMB
}

#Get-ComputerSMB servername


#############################################
#SMB Checks
#############################################
    Write-host ""
    Write-host "####################################"
    Write-host "# Now checking SMB Server settings #"
    Write-host "####################################"
    Write-host "References: https://luemmelsec.github.io/Relaying-101/" -ForegroundColor DarkGray
    Write-host "References: https://techcommunity.microsoft.com/t5/storage-at-microsoft/configure-smb-signing-with-confidence/ba-p/2418102" -ForegroundColor DarkGray
    Write-host ""

    $smbConfig = Get-SmbServerConfiguration

    # Check SMB1 settings
    if ($smbConfig.EnableSMB1Protocol) {
        Write-Host "SMB version 1 is used. No Signing available here!!!" -ForegroundColor Red
        $smb_v1 = 2
    } else {
        Write-Host "SMB version 1 is not used" -ForegroundColor Green
        $smb_v1 = 0
    }

    # Check SMB Signing settings
    if ($smbConfig.RequireSecuritySignature) {
        Write-Host "SMB signing is enabled for SMB2 and newer" -ForegroundColor Green
        $smb_sig = 0
    } else {
        Write-Host "SMB signing is disabled for SMB2 and newer" -ForegroundColor Red
        $smb_sig = 2
    }
