function Add-GHEOrgMembership {
	<#
	.SYNOPSIS
		Add a user to an organization
	.DESCRIPTION
		This cmdlet accepts a username/handle and adds it to the organization membership
	.EXAMPLE
		PS ~/ Add-GHEOrgMembership -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle MonaLisa -Organization Development -Role member
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then adds MonaLisa to the Development organization
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

		# Username/login for the user
		[Parameter(Mandatory = $true)]
		[String[]]$Handle,

		# Organization handle that the member will join
		[Parameter(Mandatory = $true)]
		[String]$Organization,

		# Role to give the user in the organization (default is 'member')
		[Parameter(Mandatory = $false)]
		[String]$Role = 'member'
	)
	Begin {
		Write-Debug -Message "Entered function: Add-GHEOrgMembership"
	}
	Process {
		Foreach ($Name in $Handle) {
			$QualifiedUrl = "https://$ComputerName/api/v3/orgs/$Organization/memberships/$Name"
			Write-Debug -Message "Qualified URL is: $QualifiedUrl"

			$Body = @{
				'role' = $Role
			}
			Write-Debug -Message "Request Body: $(Out-String -InputObject $Body)"

			$JSONData = ConvertTo-Json -InputObject $Body
			Write-Debug -Message "JSON data: $(Out-String -InputObject $JSONData)"

			Write-Debug -Message "Calling REST API"
			$Result = Invoke-WebRequest -Uri $QualifiedUrl -Method PUT -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for membership ${Name}: $(Out-String -InputObject $Result)"
		}
	}
	End {
		Write-Debug -Message 'Exiting function: Add-GHEOrgMembership'
	}
}

Write-Verbose -Message "End"

