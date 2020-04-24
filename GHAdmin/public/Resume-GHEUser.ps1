function Resume-GHEUser {
	<#
	.SYNOPSIS
		Resume a user account
	.DESCRIPTION
		This cmdlet resumes/activates a user which was previously suspended/disabled
	.EXAMPLE
		PS ~/ Resume-GHEUser -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle 'MonaLisa'
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then resumes/reactivate the account MonaLisa
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

		# Username/login of the user
		[Parameter(Mandatory = $false)]
		[String[]]$Handle,

		# Personal Access Token for authentication against the GHE API
		[Parameter(Mandatory = $true)]
		[PSCredential]$Credential
	)
	Begin {
		Write-Debug -Message 'Entered Function: Resume-GHEUser'
	}
	Process {
		Foreach ($User in $Handle) {
			Write-Debug -Message "Querying for user: $User"
			Invoke-RestMethod -Uri "https://$ComputerName/api/v3/users/$User/suspended" -Method DELETE -Authentication Basic -Credential $Credential -SkipCertificateCheck
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Resume-GHEUser'
	}
}
