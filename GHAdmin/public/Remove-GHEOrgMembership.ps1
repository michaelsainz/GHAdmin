function Remove-GHEOrgMembership {
	<#
	.SYNOPSIS
		Remove a user to an organization
	.DESCRIPTION
		This cmdlet accepts a username/handle and removes it from the organization membership
	.EXAMPLE
		PS ~/ Remove-GHEOrgMembership -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle MonaLisa -Organization Development
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then removes MonaLisa from the Development organization
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

		# Name of the user to remove from an organization
		[Parameter(Mandatory = $true)]
		[String[]]$Name,

		# Name of the organization to remove users from
		[Parameter(Mandatory = $true)]
		[String]$Organization
	)
	Begin {
		Write-Debug -Message 'Entered function: Remove-GHEOrgMembership'
	}
	Process {
		Foreach ($User in $Name) {
			Write-Debug -Message "Removing user: $User"

			$WebResult = Invoke-RestMethod -Uri "https://$ComputerName/api/v3/orgs/$Organization/memberships/$User" -Method DELETE -Authentication Basic -Credential $Cred -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for the removal of the repository: $(Out-String -InputObject $WebResult)"
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Remove-GHEOrgMembership'
	}
}
