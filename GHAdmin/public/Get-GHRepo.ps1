function Get-GHRepo {
	<#
	.SYNOPSIS
		Get information on a repository
	.DESCRIPTION
		This cmdlet retrieves information about a repository
	.EXAMPLE
		PS ~/ Get-GHRepo -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Owner MonaLisa -Name MyNewRepo
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and retrieves information about the repo MyNewRepo.
	.INPUTS
		None
	.OUTPUTS
		PSObject
			This cmdlet will return a PSObject that represents the strings of a JSON document
	.NOTES
		None
	#>
	[CmdletBinding(DefaultParameterSetName='DotCom_API')]
	Param(
		# URL of the API end point
		[Parameter(Mandatory = $false, ParameterSetName='GHE_API')]
		[String]$ComputerName,

		# Credential object for authentication against the GHE API
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_Basic')]
		[Parameter(Mandatory = $false, ParameterSetName='GHE_API')]
		[PSCredential]$Credential,

		# Personal Access Token to authenticate against GitHub.com
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $false, ParameterSetName='GHE_API')]
		[Alias('PAT')]
		[String]$GHPersonalAccessToken,

		# Name of the repository
		[Parameter(Mandatory = $true, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $true, ParameterSetName='GHE_API')]
		[String[]]$Name,

		# Custom API Version Header
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $false, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $false, ParameterSetName='GHE_API')]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json',

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory=$false, ParameterSetName='Auth_Basic')]
		[String]$OneTimePasscode
	)
	Begin {
		Write-Debug -Message "Entered function: Get-GHRepo"

		If ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
			Write-Debug -Message 'GHE_API Parameter Set'
			$BaseUrl = "https://$ComputerName/api/v3"
			Write-Debug -Message "BaseUrl is: $BaseUrl"
		}
		Else {
			Write-Debug -Message 'Default Parameter Set (github.com API)'
			$BaseUrl = 'https://api.github.com'
			Write-Debug -Message "BaseUrl is: $BaseUrl"
		}

		$Header = @{
			"Accept" = "$APIVersionHeader"
		}
		If ($GHPersonalAccessToken) {
			$Header.Add('Authorization',$GHPersonalAccessToken)
		}

		If ($OneTimePasscode) {
			$Header.Add('X-GitHub-OTP',$OneTimePasscode)
		}

		Write-Debug -Message "Current value of Headers is: $(Out-String -InputObject $Header)"
	}
	Process {
		Foreach ($Repo in $Name) {
			Write-Debug -Message "Current ParameterSet: $($PSCmdlet.ParameterSetName)"
			$RepoResolvedName = Resolve-GHRepoName -Repository $Repo
			Write-Debug -Message "Split $Repo string to $($RepoResolvedName.Owner) & $($RepoResolvedName.Name)"
			If ($PSCmdlet.ParameterSetName -eq 'DotCom_API') {
				If ($Credential) {
					Write-Debug -Message "Querying repository using Basic Authentication: $Repo"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)" -Headers $Header -Method GET -Authentication Basic -Credential $Credential
					Write-Output -InputObject $Result
				}
				ElseIf ($GHPersonalAccessToken) {
					Write-Debug -Message "Querying repository using a PAT: $Repo"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)" -Headers $Header -Method GET
					Write-Output -InputObject $Result
				}
			}
			ElseIf ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
				If ($Credential) {
					Write-Debug -Message "Querying repository: $Repo"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)" -Headers $Header -Method GET -Authentication Basic -Credential $Credential -SkipCertificateCheck
					Write-Output -InputObject $Result
				}
				ElseIf ($GHPersonalAccessToken) {
					Write-Debug -Message "Adding the PAT to the header"
					Write-Debug -Message "Querying repository: $Repo"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)" -Headers $Header -Method GET -SkipCertificateCheck
					Write-Output -InputObject $Resutl
				}
			}
		}
	}
	End {
		Write-Debug -Message "Exited function: Get-GHRepo"
	}
}
