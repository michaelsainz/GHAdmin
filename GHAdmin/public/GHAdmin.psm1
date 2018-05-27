function Invoke-GHEInitialConfiguration {
	<#
	.SYNOPSIS
		Configures the GitHub Enterprise appliance.
	.DESCRIPTION
		This cmdlet starts the initial configuration process that supplies the username, password and license file to the configuration pass.
	.EXAMPLE
		PS ~/ Invoke-GHEIntialConfiguration -ComputerName myGHEInstance.myhost.com -AdminEmail testadmin@myhost.com -AdminCredential (Get-Credential) -LicenseFile /Users/testadmin/Documents/GHELicense.ghl
		This command starts the configuration phase on "myGHEInstance.myhost.com" and once the instance is ready to accept data it will create a user with an email address of "testadmin@myhost.com" and the credentials you typed.
	.INPUTS
		None
	.OUTPUTS
		None
	.NOTES
		None
	#>
	[CmdletBinding()]
	Param(
		# File path to the GHE license file
		[Parameter(Mandatory = $true)]
		[String]$LicenseFile,

		# URL of the setup API
		[Parameter(Mandatory = $true)]
		[String]$ComputerName,

		# The first administrative user email address for the GHE virtual machine
		[Parameter(Mandatory = $true)]
		[String]$AdminEmail,

		# Credentials to create the initial administrative user
		[Parameter(Mandatory = $true)]
		[PSCredential]$AdminCredential
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
		$Result = curl -k -L -X POST $SetupUrl -F license=@$LicenseFile -F "password=$($AdminCredential.GetNetworkCredential().Password)"
		Write-Debug -Message "Result of CURL request injecting license: $(Out-String -InputObject $Result)"

		Write-Debug -Message "Starting configuration process"
		$Result = Invoke-RestMethod -Method POST -Uri "https://api_key:$($AdminCredential.GetNetworkCredential().Password)@$($ComputerName):8443/setup/api/configure" -SkipCertificateCheck
		do {
			Write-Verbose -Message "Waiting for configuration process to complete..."
			$Result = Invoke-RestMethod -Method GET -Uri "https://api_key:$($AdminCredential.GetNetworkCredential().Password)@$($ComputerName):8443/setup/api/configcheck" -SkipCertificateCheck
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
		curl -X POST -k -v -b ~/cookies -c ~/cookies -F "authenticity_token=$AuthToken" -F "user[login]=$($AdminCredential.GetNetworkCredential().UserName)" -F "user[email]=$AdminEmail" -F "user[password]=$($AdminCredential.GetNetworkCredential().Password)" -F "user[password_confirmation]=$($AdminCredential.GetNetworkCredential().Password)" -F "source_label=Detail Form" $JoinUrl >~/github-curl.out 2>&1
	}
	End {
		Write-Debug -Message 'Exiting Function: Invoke-GHEInitialConfiguration'
	}
}
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
function Get-GHOrganization {
	<#
	.SYNOPSIS
		Get information about an Organization
	.DESCRIPTION
		This cmdlet retrieves information about the specified Organization and returns JSON
	.EXAMPLE
		PS ~/ Get-GHOrganization -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle 'NCC'
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which authenticates you and then retrieves the NCC Organization which is then returned as JSON data.
	.INPUTS
		System.String
			You can pipe an array or list of handles to retrieve multiple organizations
	.OUTPUTS
		PSObject
			This cmdlet will return a PSObject that represents the strings of a JSON document
	.NOTES
		None
	#>
	[CmdletBinding()]
	Param(
		# URL of the API end point
		[Parameter(Mandatory = $false, ParameterSetName='GHE_API')]
		[String]$ComputerName,

		# Credential object for authentication against the GHE API
		[Parameter(Mandatory = $true)]
		[PSCredential]$Credential,

		# User/handle of the organization
		[Parameter(Mandatory = $true)]
		[String[]]$Handle,

		# Custom API Version Header
		[Parameter(Mandatory = $false)]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json',

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory=$false)]
		[String]$OneTimePasscode
	)
	Begin {
		Write-Debug -Message 'Entered Function: Get-GHOrganization'

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
		If ($OneTimePasscode) {
			$Header.Add('X-GitHub-OTP',$OneTimePasscode)
		}
	}
	Process {
		If ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
			Foreach ($OrgName in $Handle) {
					Write-Debug -Message "Querying for organization: $OrgName"
					Invoke-RestMethod -Uri "$BaseUrl/orgs/$OrgName" -Method GET -Headers $Header -Authentication Basic -Credential $Credential -SkipCertificateCheck
			}
		}
		Else {
			Foreach ($OrgName in $Handle) {
				Write-Debug -Message "Querying for organization: $OrgName"
				Invoke-RestMethod -Uri "$BaseUrl/orgs/$OrgName" -Method GET -Headers $Header -Authentication Basic -Credential $Credential -SkipCertificateCheck
			}
		}
	}
	End {
		Write-Debug -Message 'Exited Function: Get-GHOrganization'
	}
}
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
function Get-GHUser {
	<#
	.SYNOPSIS
		Get information on a user account
	.DESCRIPTION
		This cmdlet retrieves information on a GitHub User account
	.EXAMPLE
		PS ~/ Get-GHUser -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle 'MonaLisa'
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then retrieves information on the account MonaLisa
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
		[Parameter(Mandatory = $false, ParameterSetName='GHE_API')]
		[String]$ComputerName,

		# Username/login of the user
		[Parameter(Mandatory = $false)]
		[String[]]$Handle,

		# Personal Access Token for authentication against the GHE API
		[Parameter(Mandatory = $true)]
		[PSCredential]$Credential,

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory=$false)]
		[String]$OneTimePasscode,

		# Custom API Version Header
		[Parameter(Mandatory = $false)]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json'
	)
	Begin {
		Write-Debug -Message 'Entered Function: Get-GHUser'

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
		If ($OneTimePasscode) {
			$Header.Add('X-GitHub-OTP',$OneTimePasscode)
		}
	}
	Process {
		If ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
			Foreach ($User in $Handle) {
				Write-Debug -Message "Querying for user: $User"
				Invoke-RestMethod -Uri "https://$ComputerName/api/v3/users/$User" -Headers $Header -Method GET -Authentication Basic -Credential $Credential -SkipCertificateCheck
			}
		}
		Else {
			Foreach ($User in $Handle) {
				Write-Debug -Message "Querying for user: $User"
				Invoke-RestMethod -Uri "$BaseUrl/users/$User" -Method GET -Headers $Header -Authentication Basic -Credential $Credential -SkipCertificateCheck
			}
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Get-GHUser'
	}
}
function Remove-GHEUser {
	<#
	.SYNOPSIS
		Remove a user account
	.DESCRIPTION
		This cmdlet removes/deletes a user and all associated data under the account
	.EXAMPLE
		PS ~/ Remove-GHEUser -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle 'MonaLisa'
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then deletes the account MonaLisa
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
		Write-Debug -Message 'Entered Function: Remove-GHEUser'
	}
	Process {
		Foreach ($User in $Handle) {
			Write-Debug -Message "Querying for user: $User"
			Invoke-RestMethod -Uri "https://$ComputerName/api/v3/admin/users/$User" -Method DELETE -Authentication Basic -Credential $Credential -SkipCertificateCheck
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Remove-GHEUser'
	}
}
function Suspend-GHEUser {
	<#
	.SYNOPSIS
		Suspend a user account
	.DESCRIPTION
		This cmdlet suspends/disables a user which prevents actions from the account
	.EXAMPLE
		PS ~/ Suspend-GHEUser -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle 'MonaLisa'
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then suspends the account MonaLisa
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
		Write-Debug -Message 'Entered Function: Suspend-GHEUser'
	}
	Process {
		Foreach ($User in $Handle) {
			Write-Debug -Message "Querying for user: $User"
			Invoke-RestMethod -Uri "https://$ComputerName/api/v3/users/$User/suspended" -Method PUT -Authentication Basic -Credential $Credential -SkipCertificateCheck
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Suspend-GHEUser'
	}
}
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
function Get-GHETeam {
	<#
	.SYNOPSIS
		Get information on a team
	.DESCRIPTION
		This cmdlet retrieves information on a team
	.EXAMPLE
		PS ~/ Get-GHETeam -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Organization 'MyOrg' -Handle 'Development'
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you retrieves information on the team named Development
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

		# Personal Access Token for authentication against the GHE API
		[Parameter(Mandatory = $true)]
		[PSCredential]$Credential,

		# User/handle of the organization
		[Parameter(Mandatory = $true)]
		[String]$Handle,

		# The organization that the team will be associated with
		[Parameter(Mandatory = $true)]
		[String]$Organization
	)
	Begin {
		Write-Debug -Message 'Entered Function: Get-GHETeam'
	}
	Process {
		Foreach ($Name in $Handle) {
			Write-Debug -Message "Querying for id of team: $Name"
			$Teams = Invoke-RestMethod -Uri "https://$ComputerName/api/v3/orgs/$Organization/teams" -Method GET -Authentication Basic -Credential $Credential -SkipCertificateCheck

			Foreach ($Team in $Teams) {
				Write-Debug -Message "Checking team id: $($Team.id)"
				If ($Team.Name -eq $Handle) {
					Write-Debug -Message "Found match for team id: $($Team.id)"
					$WebResult = Invoke-RestMethod -Uri "https://$ComputerName/api/v3/teams/$($Team.id)" -Method GET -Authentication Basic -Credential $Credential -SkipCertificateCheck
				}
				Write-Output -InputObject $WebResult
			}
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Get-GHETeam'
	}
}
function New-GHETeam {
	<#
	.SYNOPSIS
		Creates a new Team
	.DESCRIPTION
		This cmdlet creates a new GitHub team within a specified organization
	.EXAMPLE
		PS ~/ New-GHETeam -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle FrontEndTeam -Organization Development -Description 'Front End Dev Team' -Repos 'Development/Website' -Privacy Secret -Maintainers MonaLisa
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then creates a new Team with the handle 'FrontEndTeam' within the 'Development' organization, adds MonaLisa as a maintainer/owner of the team and associates the 'Development/Website' repo to the Team.
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

		# Personal Access Token for authentication against the GHE API
		[Parameter(Mandatory = $true)]
		[PSCredential]$Credential,

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
			$Result = Invoke-RestMethod -Method POST -Uri $QualifiedUrl -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for team ${Team}: $(Out-String -InputObject $Result)"
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Create-GHETeam'
	}
}
function Remove-GHETeam {
	<#
	.SYNOPSIS
		Removes a team
	.DESCRIPTION
		This cmdlet removes/deletes a team
	.EXAMPLE
		PS ~/ Remove-GHETeam -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle 'FrontEndTeam' -Organization Development
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then removes the team FrontEndTeam
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

		# Username/login for the team to remove
		[Parameter(Mandatory = $true)]
		[String]$Handle,

		# Handle for the org from which the team exists in
		[Parameter(Mandatory = $true)]
		[String]$Organization
	)
	Begin {
		Write-Debug -Message "Entered function: Remove-GHETeam"
	}
	Process {
		Foreach ($Name in $Handle) {
			Write-Debug -Message "Querying for team ID"
			$Teams = Invoke-RestMethod -Uri "https://$ComputerName/api/v3/orgs/$Organization/teams" -Method GET -Authentication Basic -Credential $Credential -SkipCertificateCheck

			Foreach ($Team in $Teams) {
				If ($Team.Name -eq $Handle) {
					Write-Debug -Message "Removing team id: $($Team.id)"
					Invoke-RestMethod -Uri "https://$ComputerName/api/v3/teams/$($Team.id)" -Method DELETE -Authentication Basic -Credential $Credential -SkipCertificateCheck
				}
			}
		}
	}

	End {
		Write-Debug -Message 'Exiting function: Remove-GHETeam'
	}
}
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
function Remove-GHEOrgMembership {
	<#
	.SYNOPSIS
		Remove a user to an organization
	.DESCRIPTION
		This cmdlet accepts a username/handle and removes it from the organization membership
	.EXAMPLE
		PS ~/ Remove-GHEOrgMembership -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle MonaLisa -Organization Development
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then removes MonaLisa from the Development organization
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

		# Name of the user to remove from an organization
		[Parameter(Mandatory = $true)]
		[String[]]$Name,

		# Name of the organization to remove users from
		[Parameter(Mandatory = $true)]
		[String]$Organization
	)
	Begin {
		Write-Debug -Message 'Entered function: Remove-GHEOrgMembership'
	}
	Process {
		Foreach ($User in $Name) {
			Write-Debug -Message "Removing user: $User"

			$WebResult = Invoke-RestMethod -Uri "https://$ComputerName/api/v3/orgs/$Organization/memberships/$User" -Method DELETE -Authentication Basic -Credential $Cred -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for the removal of the repository: $(Out-String -InputObject $WebResult)"
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Remove-GHEOrgMembership'
	}
}
function Add-GHETeamMembership {
	<#
	.SYNOPSIS
		Add a user to a team
	.DESCRIPTION
		This cmdlet accepts a username/handle and adds it to a team
	.EXAMPLE
		PS ~/ Add-GHETeamMembership -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -UserHandle MonaLisa -TeamHandle FrontEndTeam -Role member
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then adds MonaLisa to the FrontEndTeam team.
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
function New-GHIssue {
	<#
	.SYNOPSIS
		Create a new GitHub Issue
	.DESCRIPTION
		This cmdlet creates a new Issue within the specified repository
	.EXAMPLE
		PS ~/ New-GHIssue -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Owner MonaLisa -Repo MyRepo -Title 'My new Issue' -Body 'Create some new documentation.' -Assignees MonaLisa
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then creates a new Issue inside the MyRepo repository that MonaLisa owns with a title and body and then finally assigns it to MonaLisa.
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
		[String]$PersonalAccessToken,

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory=$false, ParameterSetName='Auth_Basic')]
		[String]$OneTimePasscode,

		# Custom API Version Header
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $false, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $false, ParameterSetName='GHE_API')]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json',

		[Parameter(Mandatory = $true, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $true, ParameterSetName='GHE_API')]
		[String[]]$RepoName,

		# Title of the issue
		[Parameter(Mandatory = $true)]
		[String]$Title,

		# Body of the issue
		[Parameter(Mandatory = $true)]
		[String]$Body,

		# Name of the repository
		[Parameter(Mandatory = $false)]
		[String[]]$Assignees,

		# ID of the milestone to associate to the issue
		[Parameter(Mandatory=$false)]
		[Int[]]$Milestone,

		# Label to assign to the issue
		[Parameter(Mandatory=$false)]
		[String]$Label
	)
	Begin {
		Write-Debug -Message 'Entered Function: New-GHIssue'

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
		If ($PersonalAccessToken) {
			$Header.Add('Authorization',"token $PersonalAccessToken")
		}

		If ($OneTimePasscode) {
			$Header.Add('X-GitHub-OTP',$OneTimePasscode)
		}

		Write-Debug -Message "Current value of Headers is: $(Out-String -InputObject $Header)"
	}
	Process {
		foreach ($Repo in $RepoName) {
			Write-Debug -Message "Current ParameterSet: $($PSCmdlet.ParameterSetName)"
			$RepoResolvedName = Resolve-GHRepoName -Repository $Repo
			Write-Debug -Message "Split $Repo string to $($RepoResolvedName.Owner) & $($RepoResolvedName.Name)"

			$RequestBody = @{
				'title' = $Title
				'body' = $Body
				'assignees' = $(If ($Assignees.Count -eq 1){ ,@($Assignees) } Elseif ($Assignees -eq $Null) { ,@() } Else { $Assignees })
			}
			Write-Debug -Message "Request Body: $(Out-String -InputObject $RequestBody)"
			$JSONData = ConvertTo-Json -InputObject $RequestBody
			Write-Debug -Message "JSON data: $(Out-String -InputObject $JSONData)"

			If ($PSCmdlet.ParameterSetName -eq 'DotCom_API') {
				If ($Credential) {
					Write-Debug -Message "Creating issue using Basic Authentication to endpoint: $BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues" -Headers $Header -Body $JSONData -Method POST -Authentication Basic -Credential $Credential
					Write-Debug -Message "Result of REST request for issue: $(Out-String -InputObject $Result)"
				}
				ElseIf ($PersonalAccessToken) {
					Write-Debug -Message "Creating issue using a PAT to endpoint: $BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues" -Headers $Header -Body $JSONData -Method POST
					Write-Debug -Message "Result of REST request for issue: $(Out-String -InputObject $Result)"
				}
			}
			If ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
				If ($Credential) {
					Write-Debug -Message "Creating issue using Basic authentication to endpoint: $BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues" -Headers $Header -Body $JSONData -Method POST -Authentication Basic -Credential $Credential -SkipCertificateCheck
					Write-Debug -Message "Result of REST request for issue: $(Out-String -InputObject $Result)"
				}
				ElseIf ($PersonalAccessToken) {
					Write-Debug -Message "Creating issue using a PAT to endpoint: $BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues" -Headers $Header -Body $JSONData -Method POST -SkipCertificateCheck
					Write-Debug -Message "Result of REST request for issue: $(Out-String -InputObject $Result)"
				}
			}
		}
	}
	End {
		Write-Debug -Message 'Exited Function: New-GHIssue'
	}
}
function Get-GHIssue {
	<#
	.SYNOPSIS
		Retrieve an Issue from a GitHub Repository
	.DESCRIPTION
		This cmdlet retrieves a specific issue from a repository
	.EXAMPLE
		PS ~/ Get-GHEIssue -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Owner MonaLisa -Repo MyRepo -Id 16
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then retrieves the specified issue from the repository. You can specify multiple Issue id's.
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

		# Owner of the repository to retrieve an Issue
		[Parameter(Mandatory=$true)]
		[String]$Owner,

		# Name of the repository
		[Parameter(Mandatory = $true)]
		[String]$Repo,

		# ID of the issue to retrieve
		[Parameter(Mandatory = $true)]
		[String[]]$Id
	)
	Begin {
		Write-Debug -Message 'Entered Function: Get-GHEIssue'
	}
	Process {
		Foreach ($Issue in $Id) {
			$QualifiedUrl = "https://$ComputerName/api/v3/repos/$Owner/$Repo/issues/$Issue"
			Write-Debug -Message "Qualified URL is: $QualifiedUrl"

			$WebResult = Invoke-RestMethod -Uri $QualifiedUrl -Method GET -Authentication Basic -Credential $Credential -SkipCertificateCheck
			Write-Debug -Message "Result of REST request for the querying the repo: $(Out-String -InputObject $WebResult)"

			Write-Output -InputObject $WebResult
		}
	}
	End {
		Write-Debug -Message 'Exited Function: Get-GHEIssue'
	}
}
function Start-GHRepoMigration {
	<#
	.SYNOPSIS
		Start a GitHub migration job
	.DESCRIPTION
		This cmdlet begins creating a migration job and archive of the specified repositories
	.EXAMPLE
		PS C:\> <example usage>
		Explanation of what the example does
	.INPUTS
		Inputs (if any)
	.OUTPUTS
		Output (if any)
	.NOTES
		General notes
	#>
	[CmdletBinding()]
	Param (
		# The Personal Access Token with admin:org rights on github.com
		[Parameter(Mandatory=$true)]
		[Alias('GHPAT')]
		[String]$GHPersonalAccessToken,

		# Parameter help description
		[Parameter(Mandatory=$false)]
		[Switch]$LockRepositories = $false,

		# The repositories to migrate to the GHE instance
		[Parameter(Mandatory=$true)]
		[String[]]$Repositories
	)
	Begin {
		$Headers = @{
			'Authorization' = "token $GHPersonalAccessToken"
			'Accept' = 'application/vnd.github.wyandotte-preview+json'
		}
		Write-Debug -Message "Header Body: $(Out-String -InputObject $Headers)"
		$Org = Resolve-GHRepoName -Repository $Repositories[0]
	}
	Process {
		$Body = @{
			'lock_repositories' = $LockRepositories.ToBool()
			'repositories' = $Repositories
		}
		$Body = ConvertTo-Json -InputObject $Body
		Write-Debug -Message "Data Body: $(Out-String -InputObject $Body)"

		Write-Debug -Message "Calling API: https://api.github.com/orgs/$($Org.Owner)/migrations"
		Invoke-RestMethod -Uri "https://api.github.com/orgs/$($Org.Owner)/migrations" -Headers $Headers -Body $Body -Method POST
	}
	End {
		Write-Debug -Message 'Exited Function: Start-GHRepoMigration'
	}
}