<#
#https://www.terreactive.ch/de/cyber_blog/rattenfaenger-im-netz-ntlm-relaying-angriff
#https://www.security-insider.de/kerberos-ersetzt-endlich-ntlm-a-07bf445c3bb08dbb2c5bb8241a5a29a4/
#https://medium.com/tenable-techblog/decrypt-encrypted-stub-data-in-wireshark-deb132c076e7
#https://pub.fh-campuswien.ac.at/obvfcwhsacc/download/pdf/5430132?originalFilename=true
#https://www.semperis.com/blog/how-to-defend-against-ntlm-relay-attack/

Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"LMCompatibilityLevel"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0]
"NtlmMinClientSec"=dword:20080000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0]
"NTLMMinServerSec"=dword:20080000
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
