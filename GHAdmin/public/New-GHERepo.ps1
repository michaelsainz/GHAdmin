function New-GHERepo {
	<#
	.SYNOPSIS
		Creates a new Repository
	.DESCRIPTION
		This cmdlet creates a new repository
	.EXAMPLE
		PS ~/ New-GHETeam -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Name MyNewRepo -Description 'New repo for my project!' -HomePage 'https://myprojectsite.com/' -Organization Development -Private -AutoInit -LicenseTemplate 'mit'
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then creates a new Repository named MyNewRepo that has a homepage value of https://myprojectsite.com/ along with associating it within the Development organiztion, initializing it, and restricting it to be private while also associating the MIT open-source license to it.
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
		# DNS address of the primary GHE instance
		[Parameter(Mandatory = $true)]
		[String]$ComputerName,

		# Credentials for authentication to GHE
		[Parameter(Mandatory = $true)]
		[PSCredential]$Credential,

		# Name of the repository to create
		[String[]]$Name,

		# Description for the repository
		[String]$Description,

		# URL with more information about the repository
		[String]$HomePage,

		# Organization owner of the repository
		[String]$Organization,

		# Switch to create a private repository
		[Switch]$Private,

		# Switch to turn off issue tracking
		[Switch]$DisableIssues,

		# Switch to turn off project boards
		[Switch]$DisableProjects,

		# Switch to turn off wiki support
		[Switch]$DisableWiki,

		# The ID of the team that will have access to this repository
		[Int]$TeamId,

		# Switch to automatically initialize the repo with an emtpy README file and commit
		[Switch]$AutoInit,

		# The language or platform of the template to apply
		[String]$GitIgnoreTemplate,

		# The license template for the repository
		[String]$LicenseTemplate,

		# Switch to disable squash merging pull requests
		[Switch]$DisableSquash,

		# Switch to disable merge commits/pull requests
		[Switch]$DisableMerge,

		# Switch to disable rebase merge commits/pull requests
		[Switch]$DisableRebase
	)
	Begin {
		Write-Debug -Message 'Entered Function: Create-GHERepo'

		If ($Organization -ne $null) {
			Write-Debug -Message "Organization is defined, creating an Organization repo"
			$QualifiedUrl = "https://$ComputerName/api/v3/orgs/$Organization/repos"
			Write-Debug -Message "Qualified URL is: $QualifiedUrl"
		}
		Else {
			Write-Debug -Message "Organization is not defined, creating a User repo"
			$QualifiedUrl = "https://$ComputerName/api/v3/user/repos"
			Write-Debug -Message "Qualified URL is: $QualifiedUrl"
		}
	}
	Process {
		Foreach ($Repo in $Name) {
			$Body = @{
				'name' = $Repo
				'description' = $(If ($Description -eq $null){ ,@() } Else { $Description })
				'homepage' = $(If ($HomePage -eq $null){ ,@() } Else { $HomePage })
				'private' = $(If ($Private -eq $false){ $false } Else { $true })
				'has_issues' = $(If ($DisableIssues -eq $false){ $true } Else { $false })
				'has_projects' = $(If ($DisableProjects -eq $false){ $true } Else { $false })
				'has_wiki' = $(If ($DisableWiki -eq $false){ $true } Else { $false })
				'auto_init' = $(If ($AutoInit -eq $false){ $false } Else { $true })
				'gitignore_template' = $(If ($GitIgnoreTemplate -eq $null){ ,@() } Else { $GitIgnoreTemplate })
				'license_template' = $(If ($LicenseTemplate -eq $null){ ,@() } Else { $LicenseTemplate })
				'allow_squash_merge' = $(If ($DisableSquash -eq $false){ $true } Else { $false })
				'allow_merge_commit' = $(If ($DisableMerge -eq $false){ $true } Else { $false })
				'allow_rebase_merge' = $(If ($DisableRebase -eq $false){ $true } Else { $false })
			}
			If ($TeamId -ne 0){
				Write-Debug -Message "TeamId is: $TeamId"
				$Body.Add('team_id', $TeamId)
			}
			Write-Debug -Message "Request Body: $(Out-String -InputObject $Body)"

			$JSONData = ConvertTo-Json -InputObject $Body
			Write-Debug -Message "JSON data: $JSONData"

			Write-Debug -Message "Calling REST API"
			$Result = Invoke-RestMethod -Method POST -Uri $QualifiedUrl -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for repo ${repo}: $(Out-String -InputObject $Result)"
		}
	}
	End {

	}
}
