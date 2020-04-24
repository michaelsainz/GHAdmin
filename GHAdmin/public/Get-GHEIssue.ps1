function Get-GHEIssue {
	<#
	.SYNOPSIS
		Retrieve an Issue from a GitHub Repository
	.DESCRIPTION
		This cmdlet retrieves a specific issue from a repository
	.EXAMPLE
		PS ~/ Get-GHEIssue -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Owner MonaLisa -Repo MyRepo -Id 16
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then retrieves the specified issue from the repository. You can specify multiple Issue id's.
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

		# Owner of the repository to retrieve an Issue
		[Parameter(Mandatory=$true)]
		[String]$Owner,

		# Name of the repository
		[Parameter(Mandatory = $true)]
		[String]$Repo,

		# ID of the issue to retrieve
		[Parameter(Mandatory = $true)]
		[String[]]$Id
	)
	Begin {
		Write-Debug -Message 'Entered Function: Get-GHEIssue'
	}
	Process {
		Foreach ($Issue in $Id) {
			$QualifiedUrl = "https://$ComputerName/api/v3/repos/$Owner/$Repo/issues/$Issue"
			Write-Debug -Message "Qualified URL is: $QualifiedUrl"

			$WebResult = Invoke-RestMethod -Uri $QualifiedUrl -Method GET -Authentication Basic -Credential $Credential -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for the querying the repo: $(Out-String -InputObject $WebResult)"

			Write-Output -InputObject $WebResult
		}
	}
	End {
		Write-Debug -Message 'Exited Function: Get-GHEIssue'
	}
}
