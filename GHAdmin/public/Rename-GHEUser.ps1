function Rename-GHEUser {
	<#
	.SYNOPSIS
		Rename a user account
	.DESCRIPTION
		This cmdlet changes the handle of a user account
	.EXAMPLE
		PS ~/ Suspend-GHEUser -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle 'MonaLisa' -NewHandle 'Octocat'
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then changes the handle from MonaLisa to Octocat.
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
		[Parameter(Mandatory = $true)]
		[String]$Handle,

		[Parameter(Mandatory = $true)]
		[String]$NewHandle,

		# Personal Access Token for authentication against the GHE API
		[Parameter(Mandatory = $true)]
		[PSCredential]$Credential
	)
	Begin {
		Write-Debug -Message 'Entered Function: Rename-GHEUser'
	}
	Process {
		$Body = @{
			'login' = $NewHandle
		}
		Write-Debug -Message "Request Body: $(Out-String -InputObject $Body)"

		$JSONData = ConvertTo-Json -InputObject $Body
		Write-Debug -Message "JSON data: $JSONData"

		Write-Debug -Message "Querying for user: $Handle"
		$WebResults = Invoke-RestMethod -Uri "https://$ComputerName/api/v3/admin/users/$Handle" -Method PATCH -Authentication Basic -Body $JSONData -Credential $Credential -SkipCertificateCheck

		Write-Debug -Message "Response from endpoint: $WebResults"
	}
	End {
		Write-Debug -Message 'Exiting Function: Rename-GHEUser'
	}
}
