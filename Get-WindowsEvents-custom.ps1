function Get-WindowsEvents-custom {
    param(
        [string]$ComputerName,
        [string]$xmlFilePathFolder = "\\Event-Viewer\Views-ok\"
    )
 
# Use Out-GridView to select the XML file path
$xmlFilePath = Get-ChildItem -Path $xmlFilePathFolder | Out-GridView -Title "Select XML File" -PassThru
 
# Check if a file was selected
if ($xmlFilePath) {
    
    $xmlFilePath
    Get-Content $xmlFilePathFolder\$xmlFilePath
    
    # Define the XPath expression to select the QueryList node
    $xPathExpression = "//QueryList"
 
    # Use Select-Xml to retrieve the QueryList node from the XML file
    $queryList = Select-Xml -Path $xmlFilePath.FullName -XPath $xPathExpression | Select-Object -ExpandProperty Node
 
    # Convert the QueryList node to a string
    $queryListString = $queryList.OuterXml
 
    # Use the QueryList XML with the Get-WinEvent cmdlet
    Get-WinEvent -ComputerName $ComputerName -FilterXML $queryListString | Select-Object *, @{Name="Details";Expression={$_.ToXml()}} | Out-GridView -Title "Windows Events on $ComputerName"
   
}
}
 
<#
Get-WindowsEvents-custom -ComputerName Server1.bg10.bgfe.local -xmlFilePathFolder "\\Event-Viewer\Views-ok\"
Get-WindowsEvents-custom -ComputerName Server1.bg10.bgfe.local -xmlFilePathFolder "\\Event-Viewer\Views-ok\"
Get-WindowsEvents-custom -ComputerName Server1.bg10.bgfe.local -xmlFilePathFolder "\\Event-Viewer\Views-ok\"
Get-WindowsEvents-custom -ComputerName localhost -xmlFilePathFolder "\\Event-Viewer\Views-ok\"
#>
