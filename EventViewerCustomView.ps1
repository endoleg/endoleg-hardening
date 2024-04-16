
<#
	.SYNOPSIS
	The "Process Creation" Event Viewer custom view

	.PARAMETER Enable
	Create the "Process Creation" сustom view in the Event Viewer to log executed processes and their arguments

	.PARAMETER Disable
	Remove the "Process Creation" custom view in the Event Viewer

	.EXAMPLE
	EventViewerCustomView -Enable

	.EXAMPLE
	EventViewerCustomView -Disable

	.NOTES
	In order this feature to work events auditing (ProcessAudit -Enable) and command line (CommandLineProcessAudit -Enable) in process creation events will be enabled

	.NOTES
	Machine-wide
#>
function EventViewerCustomView
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			# Enable events auditing generated when a process is created (starts)
			auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable

			# Include command line in process creation events
			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force

			Set-Policy -Scope Computer -Path SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -Type DWORD -Value 1

			$XML = @"
<ViewerConfig>
	<QueryConfig>
		<QueryParams>
			<UserQuery />
		</QueryParams>
		<QueryNode>
			<Name>$($Localization.EventViewerCustomViewName)</Name>
			<Description>$($Localization.EventViewerCustomViewDescription)</Description>
			<QueryList>
				<Query Id="0" Path="Security">
					<Select Path="Security">*[System[(EventID=4688)]]</Select>
				</Query>
			</QueryList>
		</QueryNode>
	</QueryConfig>
</ViewerConfig>
"@

			if (-not (Test-Path -Path "$env:ProgramData\Microsoft\Event Viewer\Views"))
			{
				New-Item -Path "$env:ProgramData\Microsoft\Event Viewer\Views" -ItemType Directory -Force
			}

			# Save ProcessCreation.xml in the UTF-8 without BOM encoding
			Set-Content -Path "$env:ProgramData\Microsoft\Event Viewer\Views\ProcessCreation.xml" -Value $XML -Encoding Default -NoNewline -Force
		}
		"Disable"
		{
			Remove-Item -Path "$env:ProgramData\Microsoft\Event Viewer\Views\ProcessCreation.xml" -Force -ErrorAction Ignore
		}
	}
}
