function Remove-GHERepo {
	<#
	.SYNOPSIS
		Removes a repository
	.DESCRIPTION
		This cmdlet removes/deletes a repository
	.EXAMPLE
		PS ~/ Remove-GHERepo -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Name MyNewRepo -Owner MonaLisa
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and removes the repository named MyNewRepo which is owned by MonaLisa.
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

		# Name of the repository
		[Parameter(Mandatory = $true)]
		[String[]]$Name,

		# Username/login for the user/organization
		[Parameter(Mandatory = $true)]
		[String]$Owner
	)
	Begin {
		Write-Debug -Message 'Entered Function: Remove-GHERepo'
	}
	Process {
		Foreach ($Repo in $Name) {
			Write-Debug -Message "Removing repository: $Repo"

			$WebResult = Invoke-RestMethod -Uri "https://$ComputerName/api/v3/repos/$Owner/$Repo" -Method DELETE -Authentication Basic -Credential $Cred -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for the removal of the repository: $(Out-String -InputObject $WebResult)"
		}
	}
	End {
		Write-Debug -Message 'Exited Function: Remove-GHERepo'
	}
}
