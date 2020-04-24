function New-GHEUser {
	<#
	.SYNOPSIS
		Creates a new user
	.DESCRIPTION
		This cmdlet creates a new GitHub User account
	.EXAMPLE
		PS ~/ New-GHEUser -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle 'MonaLisa' -Email 'monalisa@github.com'
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then creates the MonaLisa user account and sends an email invitation to monalisa@github.com
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
		[String]$Handle,

		# Email address for the invite
		[Parameter(Mandatory = $false)]
		[String]$Email,

		# Personal Access Token for authentication against the GHE API
		[Parameter(Mandatory = $true)]
		[PSCredential]$Credential
	)
	Begin {
		Write-Debug -Message 'Entered Function: Create-GHEUser'

		$QualifiedUrl = "https://$ComputerName/api/v3/admin/users"
		Write-Debug -Message "Qualified URL is: $QualifiedUrl"
	}
	Process {
		Foreach ($User in $Handle) {
			$Body = @{
				'login' = $User
				'email' = $Email
			}
			Write-Debug -Message "Request Body: $(Out-String -InputObject $Body)"

			$JSONData = ConvertTo-Json -InputObject $Body
			Write-Debug -Message "JSON data: $JSONData"

			Write-Debug -Message "Calling REST API"
			$Result = Invoke-RestMethod -Method POST -Uri $QualifiedUrl -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for user ${User}: $(Out-String -InputObject $Result)"
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Create-GHEUser'
	}
}
