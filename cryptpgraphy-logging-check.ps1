Get-ItemPropertyValue -Path hklm:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL -Name EventLogging

<#
# enable verbose logging for the Secure Channel (SCHANNEL) security provider in Windows
# One of the things that will help you in troubleshooting any issues – is Secure Channel verbose logging.  Look at the key: HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\  for a key property called EventLogging
# This is a REG_DWORD Value from 1 to 7.  7 being the most verbose.  This setting will let you see in the System Event log for SCHANNEL events, to help understand if there is a communication mismatch, or if the client or server endpoints are still attempting an older TLS protocol:
0 - Do not log
1 - Log Error messages
2 - Log Warnings
3 - Log Error and Warning messages
4 - Log Informational and Success events
5 - Log Error, Informational and Success events
6 - Log Warnings, Informational and Success events
7 - Log Everything (Warnings, Errors, Informational and Success events
I’d recommend setting it to 3 to see errors and warnings, or 7 to see everything.  Remember to set this back to 1 when done resolving any issues.
#>
Set-ItemProperty -Path hklm:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL -Name EventLogging -Value 3
#Restart-Computer

$Date = Get-Date

$Filter = @{
    LogName      = "System"
    ProviderName = "Schannel"
    StartTime    = $Date.AddDays(-1)
    Id           = 36880
}

$Events = Get-WinEvent -FilterHashtable $Filter | foreach {
    $EventXML = ([xml]$_.ToXml()).event.userdata.eventxml
    [pscustomobject]@{    
        TimeCreated = $_.TimeCreated
        MachineName = $_.MachineName
        Protocol = $EventXML.protocol
        CipherSuite = $EventXML.CipherSuite  
        TargetName = $EventXML.TargetName  
        LocalCertSubjectName = $EventXML.LocalCertSubjectName  
        RemoteCertSubjectName = $EventXML.RemoteCertSubjectName    
    }
}

Write-Output "`nProtocol"
$Events | group Protocol | select count, name
Write-Output "`nCipherSuite"
$Events | group CipherSuite | select count, name
Write-Output "`nLocalCertSubjectName"
$Events | group LocalCertSubjectName | select count, name
Write-Output "`nRemoteCertSubjectName"
$Events | group RemoteCertSubjectName | select count, name
Write-Output "`nTargetName"
$Events | group TargetName | select count, name


<#
    #disable logging
    Set-ItemProperty -Path hklm:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL -Name EventLogging -Value 1 
    #Restart-Computer
#>
