function Remove-GHETeam {
	<#
	.SYNOPSIS
		Removes a team
	.DESCRIPTION
		This cmdlet removes/deletes a team
	.EXAMPLE
		PS ~/ Remove-GHETeam -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle 'FrontEndTeam' -Organization Development
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then removes the team FrontEndTeam
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

		# Username/login for the team to remove
		[Parameter(Mandatory = $true)]
		[String]$Handle,

		# Handle for the org from which the team exists in
		[Parameter(Mandatory = $true)]
		[String]$Organization
	)
	Begin {
		Write-Debug -Message "Entered function: Remove-GHETeam"
	}
	Process {
		Foreach ($Name in $Handle) {
			Write-Debug -Message "Querying for team ID"
			$Teams = Invoke-RestMethod -Uri "https://$ComputerName/api/v3/orgs/$Organization/teams" -Method GET -Authentication Basic -Credential $Credential -SkipCertificateCheck

			Foreach ($Team in $Teams) {
				If ($Team.Name -eq $Handle) {
					Write-Debug -Message "Removing team id: $($Team.id)"
					Invoke-RestMethod -Uri "https://$ComputerName/api/v3/teams/$($Team.id)" -Method DELETE -Authentication Basic -Credential $Credential -SkipCertificateCheck
				}
			}
		}
	}

	End {
		Write-Debug -Message 'Exiting function: Remove-GHETeam'
	}
}
