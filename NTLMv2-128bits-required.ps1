<#
#https://www.terreactive.ch/de/cyber_blog/rattenfaenger-im-netz-ntlm-relaying-angriff
#https://www.security-insider.de/kerberos-ersetzt-endlich-ntlm-a-07bf445c3bb08dbb2c5bb8241a5a29a4/
#https://medium.com/tenable-techblog/decrypt-encrypted-stub-data-in-wireshark-deb132c076e7
#https://pub.fh-campuswien.ac.at/obvfcwhsacc/download/pdf/5430132?originalFilename=true
#https://www.semperis.com/blog/how-to-defend-against-ntlm-relay-attack/

#eventlog
eventvwr.exe /l:C:\Windows\System32\Winevt\Logs\Microsoft-Windows-NTLM%4Operational.evtx

Microsoft-Windows-NTLM/Operational
100 NTLM authentication failed because the account was a member of the Protected User group....
 101 NTLM authentication failed because access control restrictions are required....
 301 NTLM authentication succeded, but it will fail when Authentication Policy is enforced because access control restrictions are required....
4001 NTLM client blocked: Outgoing NTLM authentication traffic to remote servers that is blocked....
4002 NTLM server blocked: Incoming NTLM traffic to servers that is blocked...
4003 NTLM server blocked in the domain: NTLM authentication in this domain that is blocked...
4010 NTLM Minimum Client Security Block:...
4011 NTLM Minimum Server Security Block:...
4012 NTLM client used the domain password. The attempt to use the DC-generated NTLM secret failed, and fallback to the domain password succeeded....
4013 Attempt to use NTLMv1 failed....
8001 NTLM client blocked audit: Audit outgoing NTLM authentication traffic that would be blocked....
8002 NTLM server blocked audit: Audit Incoming NTLM Traffic that would be blocked...
8003 NTLM server blocked in the domain audit: Audit NTLM authentication in this domain...

#Audit NTLMv1 24 hours
$Events = Get-WinEvent -Logname Security -FilterXPath "Event[System[(EventID=4624)]] and Event[EventData[Data[@Name='LmPackageName']='NTLM V1']] and Event[System[TimeCreated[@SystemTime >= '$((Get-Date).AddDays(-1).ToString("s"))']]]" |
    Select-Object TimeCreated, @{Name='UserName'; Expression={$_.Properties[5].Value}}, 
        @{Name='WorkstationName'; Expression={$_.Properties[11].Value}}, 
        @{Name='LogonType'; Expression={$_.Properties[8].Value}}, 
        @{Name='AuthenticationPackageName'; Expression={$_.Properties[10].Value}},
        @{Name='LmPackageName'; Expression={$_.Properties[14].Value}},
        @{Name='ImpersonationLevel'; Expression={$_.Properties[20].Value}}
$Events | Out-GridView

#Audit NTLMv2 last 24 hours
$Events = Get-WinEvent -Logname Security -FilterXPath "Event[System[(EventID=4624)]] and Event[EventData[Data[@Name='LmPackageName']='NTLM V2']] and Event[System[TimeCreated[@SystemTime >= '$((Get-Date).AddDays(-1).ToString("s"))']]]" |
    Select-Object TimeCreated, @{Name='UserName'; Expression={$_.Properties[5].Value}}, 
        @{Name='WorkstationName'; Expression={$_.Properties[11].Value}}, 
        @{Name='LogonType'; Expression={$_.Properties[8].Value}}, 
        @{Name='AuthenticationPackageName'; Expression={$_.Properties[10].Value}},
        @{Name='LmPackageName'; Expression={$_.Properties[14].Value}},
        @{Name='ImpersonationLevel'; Expression={$_.Properties[20].Value}}
$Events | Out-GridView

# Activate Audits for NTLM-Auth on DomainController only!
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictSendingNTLMTraffic" -Value 2

# Activate Audits for NTLM-Auth (ReceivingNTLMTraffic) - on every computer
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic" -Value 1

# Activate Audits for NTLM-Auth (OutgoingNTLMTraffic) - on every computer
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditOutgoingNTLMTraffic" -Value 1

#>

write-host "Get lmcompatibilitylevel"
(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").lmcompatibilitylevel

write-verbose "Check if the HKLM:\SYSTEM\CurrentControlSet\Control\Lsa registry key exists, If not, create it" -verbose
if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa") -ne $true) {New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -force -ea SilentlyContinue}

write-verbose "Check if the HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 registry key exists, If not, create it" -verbose
if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0") -ne $true) {New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -force -ea SilentlyContinue}

write-verbose "Set the LMCompatibilityLevel registry value to 3 in the HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -verbose
write-verbose "This value determines the compatibility with older LAN Manager authentication protocols." -verbose
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LMCompatibilityLevel' -Value 5 -PropertyType DWord -Force -ea SilentlyContinue
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> 
# "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM".
# https://www.stigviewer.com/stig/microsoft_windows_server_2019/2023-09-11/finding/V-205919
<#
0 LM- und NTLM-Antworten senden: 
Von Clients wird LM- und NTLM-Authentifizierung, jedoch nie NTLMv2-Sitzungssicherheit verwendet; Von Domänencontrollern werden LM-, NTLM- und NTLMv2-Authentifizierung akzeptiert.
1 LM- und NTLM-Antworten senden (NTLMv2-Sitzungssicherheit verwenden, wenn ausgehandelt): 
Von Clients werden LM- und NTLM-Authentifizierung sowie NTLMv2-Sitzungssicherheit verwendet, wenn diese vom Server unterstützt wird; von Domänencontrollern werden LM-, NTLM- und NTLMv2-Authentifizierung akzeptiert.
2 Nur NTLM-Antworten senden: 
Von Clients wird nur NTLM-Authentifizierung verwendet. NTLMv2-Sitzungssicherheit wird verwendet, wenn diese vom Server unterstützt wird; von Domänencontrollern werden LM-, NTLM- und NTLMv2-Authentifizierung akzeptiert.
3 Nur NTLMv2-Antworten senden: 
Von Clients wird nur NTLMv2-Authentifizierung verwendet. NTLMv2-Sitzungssicherheit wird verwendet, wenn diese vom Server unterstützt wird; von Domänencontrollern werden LM-, NTLM- und NTLMv2-Authentifizierung akzeptiert.
4 Nur NTLMv2-Antworten senden. LM verweigern: 
Von Clients wird nur NTLMv2-Authentifizierung verwendet. NTLMv2-Sitzungssicherheit wird verwendet, wenn diese vom Server unterstützt wird; von Domänencontrollern wird LM verweigert (akzeptiert werden nur NTLM- und NTLMv2-Authentifizierung).
5 Nur NTLMv2-Antworten senden. LM und NTLM verweigern: 
Von Clients wird nur NTLMv2-Authentifizierung verwendet, NTLMv2-Sitzungssicherheit wird verwendet, wenn diese vom Server unterstützt wird. Von Domänencontrollern werden LM und NTLM verweigert (nur NTLMv2-Authentifizierung wird akzeptiert).
#>

write-host "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients to Require NTLMv2 session security and Require 128-bit encryption (all options selected)."

write-verbose "Set the NtlmMinClientSec registry value to 537395200 in the HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 key" -verbose
write-verbose "This value specifies the minimum security configuration for NTLM clients." -verbose
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinClientSec' -Value 537395200 -PropertyType DWord -Force -ea SilentlyContinue
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> 
# "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients" to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options selected).
# https://www.stigviewer.com/stig/windows_server_2016/2020-06-16/finding/V-73695

write-verbose "Set the NTLMMinServerSec registry value to 537395200 in the HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 key" -verbose
write-verbose "This value specifies the minimum security configuration for NTLM servers." -verbose
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NTLMMinServerSec' -Value 537395200 -PropertyType DWord -Force -ea SilentlyContinue
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> 
# "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers" to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options selected).
# https://www.stigviewer.com/stig/windows_server_2016/2020-06-16/finding/V-73697


