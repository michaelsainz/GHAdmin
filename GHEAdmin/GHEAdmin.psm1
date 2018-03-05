function Invoke-GHEInitialConfiguration {
	[CmdletBinding()]
	Param(
		# File path to the GHE license file
		[Parameter(Mandatory = $true)]
		[String]$LicenseFile,

		# URL of the setup API
		[Parameter(Mandatory = $true)]
		[String]$ComputerName,

		# The management password for the GHE virtual machine
		[Parameter(Mandatory = $true)]
		[String]$MgmtPassword,

		# The first administrative user for the GHE virtual machine
		[Parameter(Mandatory = $true)]
		[String]$AdminUser,

		# The first administrative user email address for the GHE virtual machine
		[Parameter(Mandatory = $true)]
		[String]$AdminEmail
	)
	Begin {
		Write-Debug -Message 'Entered Function: Invoke-GHEInitialConfiguration'

		$SetupUrl = "https://$ComputerName/setup/api/start"
		Write-Debug -Message "Qualified URL is: $SetupUrl"
		$JoinUrl = "https://$ComputerName/join"

		If (-not (Test-Path -Path $LicenseFile)) {
			Write-Debug -Message "The license file path did not resolve: $LicensePath"
		}
	}
	Process {
		<#
		We have to use CURL instead of Invoke-RestMethod or Invoke-WebRequest
		as they don't fully support multipart/form-data yet
		#>
		Write-Debug -Message "Calling CURL to inject license and initial password"
		$Result = curl -k -L -X POST $SetupUrl -F license=@$LicenseFile -F "password=$($Credential.GetNetworkCredential().Password)"
		Write-Debug -Message "Result of CURL request injecting license: $(Out-String -InputObject $Result)"

		Write-Debug -Message "Starting configuration process"
		$Result = Invoke-RestMethod -Method POST -Uri "https://api_key:$($Credential.GetNetworkCredential().Password)@$($ComputerName):8443/setup/api/configure" -SkipCertificateCheck
		do {
			Write-Verbose -Message "Waiting for configuration process to complete..."
			$Result = Invoke-RestMethod -Method GET -Uri "https://api_key:$($Credential.GetNetworkCredential().Password)@$($ComputerName):8443/setup/api/configcheck" -SkipCertificateCheck
			Write-Debug -Message "Current result of configuration process: $(Out-String -InputObject $Result.Status)"
			Start-Sleep -Seconds 30
		} until ($Result.status -eq 'success' -or $Result.status -eq 'failed')

		Write-Debug -Message "Creating first user"
		$Result = curl -k -v -L -c ~/cookies $JoinUrl >~/github-curl.out
		Write-Debug -Message "Result of CURL request for grabbing the Authentication Token: $(Out-String -InputObject $Result)"
		$AuthFullString = (grep 'authenticity_token' ~/github-curl.out | head -1)
		Write-Debug -Message "Current value of AuthFullString: $AuthFullString"
		$RegexPattern = '(?<=value=")(.*?)(?=")'
		$AuthToken = ([regex]::matches($AuthFullString, $RegexPattern)).Value[1]
		Write-Debug -Message "Current value of AuthToken: $AuthToken"
		curl -X POST -k -v -b ~/cookies -c ~/cookies -F "authenticity_token=$AuthToken" -F "user[login]=$($Credential.GetNetworkCredential().UserName)" -F "user[email]=$AdminEmail" -F "user[password]=$($Credential.GetNetworkCredential().Password)" -F "user[password_confirmation]=$($Credential.GetNetworkCredential().Password)" -F "source_label=Detail Form" $JoinUrl >~/github-curl.out 2>&1
	}
	End {
		Write-Debug -Message 'Exiting Function: Invoke-GHEInitialConfiguration'
	}
}
function New-GHEOrganization {
	[CmdletBinding()]
	Param(
		# URL of the API end point
		[Parameter(Mandatory = $true)]
		[String]$ComputerName,

		# Credential object for authentication against the GHE API
		[Parameter(Mandatory = $true)]
		[pscredential]$Credential,

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

		$Headers = @{
			'Authorization' = "token $AuthToken"
			'Accept' = 'application/vnd.github.v3+json'
		}
		Write-Debug -Message "HTTP Headers: $(Out-String -InputObject $Headers)"
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
			$Result = Invoke-RestMethod -Method POST -Uri $QualifiedUrl -Headers $Headers -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for organization ${OrgHandle}: $(Out-String -InputObject $Result)"
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: New-GHEOrganization'
	}
}
function New-GHEUser {
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
		[String]$AuthToken
	)
	Begin {
		Write-Debug -Message 'Entered Function: Create-GHEUser'

		$QualifiedUrl = "https://$ComputerName/api/v3/admin/users"
		Write-Debug -Message "Qualified URL is: $QualifiedUrl"

		$Headers = @{
			'Authorization' = "token $AuthToken"
			'Accept' = 'application/vnd.github.v3+json'
		}
		Write-Debug -Message "HTTP Headers: $(Out-String -InputObject $Headers)"
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
			$Result = Invoke-RestMethod -Method POST -Uri $QualifiedUrl -Headers $Headers -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for user ${User}: $(Out-String -InputObject $Result)"
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Create-GHEUser'
	}
}
function New-GHETeam {
	[CmdletBinding()]
	Param(
		# URL of the API end point
		[Parameter(Mandatory = $true)]
		[String]$ComputerName,

		# Personal Access Token for authentication against the GHE API
		[Parameter(Mandatory = $true)]
		[String]$AuthToken,

		# User/handle of the organization
		[Parameter(Mandatory = $true)]
		[String]$Handle,

		# The organization that the team will be associated with
		[Parameter(Mandatory = $true)]
		[String]$Organization,

		# Description of the team
		[Parameter(Mandatory = $false)]
		[String]$Description,

		# Repositories that the team is associated with
		[Parameter(Mandatory = $false)]
		[String[]]$Repos,

		# Level of privacy the team should have
		[Parameter(Mandatory = $false)]
		[String]$Privacy,

		# List of maintainers/owners of the team
		[Parameter(Mandatory = $false)]
		[String[]]$Maintainers
	)
	Begin {
		Write-Debug -Message 'Entered Function: Create-GHETeam'

		$QualifiedUrl = "https://$ComputerName/api/v3/orgs/$Organization/teams"
		Write-Debug -Message "Qualified URL is: $QualifiedUrl"

		$Headers = @{
			'Authorization' = "token $AuthToken"
			'Accept' = 'application/vnd.github.v3+json'
		}
		Write-Debug -Message "HTTP Headers: $(Out-String -InputObject $Headers)"
	}
	Process {
		Foreach ($Team in $Handle) {
			$Body = @{
				'name' = $Handle
				'description' = $(If ($Description -eq $null){ ,@() } Else { $Description })
				'maintainers' = $(If ($Maintainers.Count -eq 1){ ,@($Maintainers) } Elseif ($Maintainers -eq $Null) { ,@() } Else { $Maintainers })
				'repo_names' = $(If ($Repos.Count -eq 1){ ,@($Repos) } Elseif ($Repos -eq $Null) { ,@() } Else { $Repos })
				'privacy' = $(If ($Privacy -eq $null){ ,@() } Else { $Privacy })
			}
			Write-Debug -Message "Request Body: $(Out-String -InputObject $Body)"

			$JSONData = ConvertTo-Json -InputObject $Body
			Write-Debug -Message "JSON data: $JSONData"

			Write-Debug -Message "Calling REST API"
			$Result = Invoke-RestMethod -Method POST -Uri $QualifiedUrl -Headers $Headers -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for team ${Team}: $(Out-String -InputObject $Result)"
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Create-GHETeam'
	}
}
function New-GHERepo {
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
function Add-GHEOrgMembership {
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
function Add-GHETeamMembership {
	[CmdletBinding()]
	Param(
		# URL of the API end point
		[Parameter(Mandatory = $true)]
		[String]$ComputerName,

		# Credential object for authentication against the GHE API
		[Parameter(Mandatory = $true)]
		[PSCredential]$Credential,

		# Username/login for the team
		[Parameter(Mandatory = $true)]
		[String]$TeamHandle,

		# Username/login for the user
		[Parameter(Mandatory = $true)]
		[String[]]$UserHandle,

		# The role that the user will have on the specified team
		[Parameter(Mandatory = $true)]
		[String]$Role
	)

	Begin {
		Write-Debug -Message "Entered function: Add-GHETeamMembership"
	}
	Process {
		Foreach ($Name in $Handle) {
			$QualifiedUrl = "https://$ComputerName/api/v3/teams/$TeamHandle/memberships/$UserHandle"
			Write-Debug -Message "Qualified URL is: $QualifiedUrl"

			$Body = @{
				'role' = $Role
			}

			$JSONData = ConvertTo-Json -InputObject $Body
			Write-Debug -Message "JSON data: $(Out-String -InputObject $JSONData)"

			Write-Debug -Message "Calling REST API"
			$Result = Invoke-WebRequest -Uri $QualifiedUrl -Method PUT -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for membership ${Name}: $(Out-String -InputObject $Result)"

		}
	}

	End {
		Write-Debug -Message 'Exiting function: Add-GHETeamMembership'

	}
}
