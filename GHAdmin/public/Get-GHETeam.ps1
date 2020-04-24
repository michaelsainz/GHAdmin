function Get-GHETeam {
	<#
	.SYNOPSIS
		Get information on a team
	.DESCRIPTION
		This cmdlet retrieves information on a team
	.EXAMPLE
		PS ~/ Get-GHETeam -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Organization 'MyOrg' -Handle 'Development'
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you retrieves information on the team named Development
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
		[String]$Organization
	)
	Begin {
		Write-Debug -Message 'Entered Function: Get-GHETeam'
	}
	Process {
		Foreach ($Name in $Handle) {
			Write-Debug -Message "Querying for id of team: $Name"
			$Teams = Invoke-RestMethod -Uri "https://$ComputerName/api/v3/orgs/$Organization/teams" -Method GET -Authentication Basic -Credential $Credential -SkipCertificateCheck

			Foreach ($Team in $Teams) {
				Write-Debug -Message "Checking team id: $($Team.id)"
				If ($Team.Name -eq $Handle) {
					Write-Debug -Message "Found match for team id: $($Team.id)"
					$WebResult = Invoke-RestMethod -Uri "https://$ComputerName/api/v3/teams/$($Team.id)" -Method GET -Authentication Basic -Credential $Credential -SkipCertificateCheck
				}
				Write-Output -InputObject $WebResult
			}
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Get-GHETeam'
	}
}
