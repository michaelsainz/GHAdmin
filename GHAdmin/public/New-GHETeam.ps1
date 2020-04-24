function New-GHETeam {
	<#
	.SYNOPSIS
		Creates a new Team
	.DESCRIPTION
		This cmdlet creates a new GitHub team within a specified organization
	.EXAMPLE
		PS ~/ New-GHETeam -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle FrontEndTeam -Organization Development -Description 'Front End Dev Team' -Repos 'Development/Website' -Privacy Secret -Maintainers MonaLisa
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then creates a new Team with the handle 'FrontEndTeam' within the 'Development' organization, adds MonaLisa as a maintainer/owner of the team and associates the 'Development/Website' repo to the Team.
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

		# Personal Access Token for authentication against the GHE API
		[Parameter(Mandatory = $true)]
		[PSCredential]$Credential,

		# User/handle of the organization
		[Parameter(Mandatory = $true)]
		[String]$Handle,

		# The organization that the team will be associated with
		[Parameter(Mandatory = $true)]
		[String]$Organization,

		# Description of the team
		[Parameter(Mandatory = $false)]
		[String]$Description,

		# Repositories that the team is associated with
		[Parameter(Mandatory = $false)]
		[String[]]$Repos,

		# Level of privacy the team should have
		[Parameter(Mandatory = $false)]
		[String]$Privacy,

		# List of maintainers/owners of the team
		[Parameter(Mandatory = $false)]
		[String[]]$Maintainers
	)
	Begin {
		Write-Debug -Message 'Entered Function: Create-GHETeam'

		$QualifiedUrl = "https://$ComputerName/api/v3/orgs/$Organization/teams"
		Write-Debug -Message "Qualified URL is: $QualifiedUrl"
	}
	Process {
		Foreach ($Team in $Handle) {
			$Body = @{
				'name' = $Handle
				'description' = $(If ($Description -eq $null){ ,@() } Else { $Description })
				'maintainers' = $(If ($Maintainers.Count -eq 1){ ,@($Maintainers) } Elseif ($Maintainers -eq $Null) { ,@() } Else { $Maintainers })
				'repo_names' = $(If ($Repos.Count -eq 1){ ,@($Repos) } Elseif ($Repos -eq $Null) { ,@() } Else { $Repos })
				'privacy' = $(If ($Privacy -eq $null){ ,@() } Else { $Privacy })
			}
			Write-Debug -Message "Request Body: $(Out-String -InputObject $Body)"

			$JSONData = ConvertTo-Json -InputObject $Body
			Write-Debug -Message "JSON data: $JSONData"

			Write-Debug -Message "Calling REST API"
			$Result = Invoke-RestMethod -Method POST -Uri $QualifiedUrl -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for team ${Team}: $(Out-String -InputObject $Result)"
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Create-GHETeam'
	}
}
