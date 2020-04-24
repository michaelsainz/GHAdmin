function Set-GHERepoProperty {
	<#
	.SYNOPSIS
		Sets properties on a repository
	.DESCRIPTION
		This cmdlet sets specific properties on a repo
	.EXAMPLE
		PS ~/ Set-GHERepoProperty -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Owner MonaLisa -Name MyNewRepo -Property 'default_branch' -Value 'dev_branch'
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and sets the default branch on the repository to dev_branch.
	.EXAMPLE
		PS C:\ $MyHashTable = @{description = 'This is a new description for my repo!';homepage = 'https://mynewhomepage.net'}
		PS ~/ Set-GHERepoProperty -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Owner MonaLisa -Name MyNewRepo -HashTable $MyHashTable
		The first command creates a PowerShell hashtable with keys and values of repo properties (description & homepage) and stores them in the $MyHashTable object. The second command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and passes the hashtable which contains the properties to set.
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

		# Handle/Owner of the repository
		[Parameter(Mandatory = $true)]
		[String]$Owner,

		# Name of the repository
		[Parameter(Mandatory = $true)]
		[String[]]$Name,

		# The hashtable that has the properties and values to update on the repository
		[Parameter(Mandatory = $false)]
		[HashTable]$Data,

		# The property you want to update on the repository
		[Parameter(Mandatory = $false)]
		[String]$Property,

		# The property value you want to update on the repository
		[Parameter(Mandatory = $false)]
		[String]$Value
	)
	Begin {
		Write-Debug -Message 'Entered Function: Set-GHERepoProperty'
	}
	Process {
		If ($Data) {
			Write-Debug -Message 'Updating the repo using the bulk data hashtable method'
			Foreach ($Repo in $Name) {
				Write-Debug -Message "Setting properties on repo: $Repo"

				If (($Data.ContainsKey('name')) -eq $false) {
					Write-Debug -Message '$Data does not have a name property, adding property.'
					$Data.Add('name', $Repo)
				}
				Write-Debug -Message "Value of `$Data object: $(Out-String -InputObject $Data)"

				$Body = ConvertTo-Json -InputObject $Data
				Write-Debug -Message "Current value of JSON: $(Out-String -InputObject $Body)"

				$WebResult = Invoke-RestMethod -Uri "https://$ComputerName/api/v3/repos/$Owner/$Repo" -Method PATCH -Body $Body -Authentication Basic -Credential $Credential -SkipCertificateCheck
				Write-Debug -Message "Result of REST request for repo ${Repo}: $(Out-String -InputObject $WebResult)"
			}
		}
		Else {
			Write-Debug -Message 'Updating the repo using the single property method'
			Foreach ($Repo in $Name) {
				Write-Debug -Message "Setting property `"$Property`" to `"$Value`" on repo: $Repo"

				$PSPayload = @{
					'name' = $Repo
					$Property = $Value
				}
				Write-Debug -Message "Value of `$PSPayload: $(Out-String -InputObject $PSPayload)"

				$Body = ConvertTo-Json -InputObject $PSPayload
				Write-Debug -Message "Value of JSON object: $(Out-String -InputObject $Body)"

				$WebResult = Invoke-RestMethod -Uri "https://$ComputerName/api/v3/repos/$Owner/$Repo" -Method PATCH -Body $Body -Authentication Basic -Credential $Credential -SkipCertificateCheck
				Write-Debug -Message "Result of REST request for repo ${Repo}: $(Out-String -InputObject $WebResult)"
			}
		}
	}
	End{
		Write-Debug -Message 'Exited Function: Set-GHERepoProperty'
	}
}
