function Add-GHETeamMembership {
	<#
	.SYNOPSIS
		Add a user to a team
	.DESCRIPTION
		This cmdlet accepts a username/handle and adds it to a team
	.EXAMPLE
		PS ~/ Add-GHETeamMembership -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -UserHandle MonaLisa -TeamHandle FrontEndTeam -Role member
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then adds MonaLisa to the FrontEndTeam team.
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

		# Username/login for the team
		[Parameter(Mandatory = $true)]
		[String]$TeamHandle,

		# Username/login for the user
		[Parameter(Mandatory = $true)]
		[String[]]$UserHandle,

		# The role that the user will have on the specified team
		[Parameter(Mandatory = $true)]
		[String]$Role
	)
	Begin {
		Write-Debug -Message "Entered function: Add-GHETeamMembership"
	}
	Process {
		Foreach ($Name in $Handle) {
			$QualifiedUrl = "https://$ComputerName/api/v3/teams/$TeamHandle/memberships/$UserHandle"
			Write-Debug -Message "Qualified URL is: $QualifiedUrl"

			$Body = @{
				'role' = $Role
			}

			$JSONData = ConvertTo-Json -InputObject $Body
			Write-Debug -Message "JSON data: $(Out-String -InputObject $JSONData)"

			Write-Debug -Message "Calling REST API"
			$Result = Invoke-WebRequest -Uri $QualifiedUrl -Method PUT -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for membership ${Name}: $(Out-String -InputObject $Result)"

		}
	}

	End {
		Write-Debug -Message 'Exiting function: Add-GHETeamMembership'

	}
}
