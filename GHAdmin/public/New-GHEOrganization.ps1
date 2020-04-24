function New-GHEOrganization {
	<#
	.SYNOPSIS
		Create a new Organization
	.DESCRIPTION
		This cmdlet creates a new GitHub Organization account for which you can place repositories and teams within.
	.EXAMPLE
		PS ~/ New-GHEOrganization -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -DisplayName 'The New Coffee Company' -Handle 'NCC' -AdminName 'MonaLisa'
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then creates the NCC organization account with the display name of 'The New Coffee Company' and the user MonaLisa is the administrator.
	.INPUTS
		None
	.OUTPUTS
		None
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

		# Display name of the Organization
		[Parameter(Mandatory = $true)]
		[String]$DisplayName,

		# User account who will be the administrator of the organization
		[Parameter(Mandatory = $true)]
		[String]$AdminName,

		# User/handle of the organization
		[Parameter(Mandatory = $true)]
		[String]$Handle
	)
	Begin {
		Write-Debug -Message 'Entered Function: New-GHEOrganization'

		$QualifiedUrl = "https://$ComputerName/api/v3/admin/organizations"
		Write-Debug -Message "Qualified URL is: $QualifiedUrl"
	}
	Process {
		Foreach ($OrgHandle in $Handle) {
			$Body = @{
				'login' = $OrgHandle
				'admin' = $AdminName
				'profile_name' = $DisplayName
			}
			Write-Debug -Message "Request Body: $(Out-String -InputObject $Body)"

			$JSONData = ConvertTo-Json -InputObject $Body
			Write-Debug -Message "JSON data: $JSONData"

			Write-Debug -Message 'Calling REST API'
			$Result = Invoke-RestMethod -Method POST -Uri $QualifiedUrl -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for organization ${OrgHandle}: $(Out-String -InputObject $Result)"
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: New-GHEOrganization'
	}
}
