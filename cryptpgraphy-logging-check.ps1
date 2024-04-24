Get-ItemPropertyValue -Path hklm:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL -Name EventLogging

#enable logging
Set-ItemProperty -Path hklm:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL -Name EventLogging -Value 7
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


#disable logging
Set-ItemProperty -Path hklm:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL -Name EventLogging -Value 1 
#Restart-Computer
