function New-GHEIssue {
	<#
	.SYNOPSIS
		Create a new GitHub Issue
	.DESCRIPTION
		This cmdlet creates a new Issue within the specified repository
	.EXAMPLE
		PS ~/ New-GHEIssue -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Owner MonaLisa -Repo MyRepo -Title 'My new Issue' -Body 'Create some new documentation.' -Assignees MonaLisa
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then creates a new Issue inside the MyRepo repository that MonaLisa owns with a title and body and then finally assigns it to MonaLisa.
	.INPUTS
		None
	.OUTPUTS
		PSObject
			This cmdlet will return a PSObject that represents the strings of a JSON document
	.NOTES
		None
	#>
	[CmdletBinding()]
	Param(
		# URL of the API end point
		[Parameter(Mandatory = $true)]
		[String]$ComputerName,

		# Credential object for authentication against the GHE API
		[Parameter(Mandatory = $true)]
		[PSCredential]$Credential,

		# Owner of the repository to create an Issue
		[Parameter(Mandatory=$true)]
		[String]$Owner,

		# Name of the repository
		[Parameter(Mandatory = $true)]
		[String]$Repo,

		# Title of the issue
		[Parameter(Mandatory = $true)]
		[String]$Title,

		# Body of the issue
		[Parameter(Mandatory = $true)]
		[String]$Body,

		# Name of the repository
		[Parameter(Mandatory = $false)]
		[String[]]$Assignees,

		# ID of the milestone to associate to the issue
		[Parameter(Mandatory=$false)]
		[Int[]]$Milestone,

		# Label to assign to the issue
		[Parameter(Mandatory=$false)]
		[String]$Label
	)
	Begin {
		Write-Debug -Message 'Entered Function: New-GHEIssue'
	}
	Process {
		$QualifiedUrl = "https://$ComputerName/api/v3/repos/$Owner/$Repo/issues"
		Write-Debug -Message "Qualified URL is: $QualifiedUrl"

		$RequestBody = @{
			'title' = $Title
			'body' = $Body
			'assignees' = $(If ($Assignees.Count -eq 1){ ,@($Assignees) } Elseif ($Assignees -eq $Null) { ,@() } Else { $Assignees })
		}
		Write-Debug -Message "Request Body: $(Out-String -InputObject $RequestBody)"

		$JSONData = ConvertTo-Json -InputObject $RequestBody
		Write-Debug -Message "JSON data: $JSONData"

		Write-Debug -Message "Calling REST API"
		$Result = Invoke-RestMethod -Method POST -Uri $QualifiedUrl -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
		Write-Debug -Message "Result of REST request for issue: $(Out-String -InputObject $Result)"

		Write-Output -InputObject $Result
	}
	End {
		Write-Debug -Message 'Exited Function: New-GHEIssue'
	}
}
