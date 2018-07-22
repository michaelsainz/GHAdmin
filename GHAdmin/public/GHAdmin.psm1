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
	[CmdletBinding(DefaultParameterSetName='Auth_Basic')]
	Param(
		# URL of the API end point
		[Parameter(Mandatory = $false)]
		[String]$ComputerName,

		# Credential object for authentication against the GHE API
		[Parameter(Mandatory = $true, ParameterSetName='Auth_Basic')]
		[PSCredential]$Credential,

		# Personal Access Token to authenticate against GitHub.com
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[Alias('PAT')]
		[String]$PersonalAccessToken,

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory=$false, ParameterSetName='Auth_Basic')]
		[String]$OneTimePasscode,

		# Custom API Version Header
		[Parameter(Mandatory = $false, ParameterSetName='Auth_Basic')]
		[Parameter(Mandatory = $false, ParameterSetName='Auth_PAT')]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json',

		# Display name of the Organization
		[Parameter(Mandatory = $true, ParameterSetName='Auth_Basic')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[String]$DisplayName,

		# User account who will be the administrator of the organization
		[Parameter(Mandatory = $true, ParameterSetName='Auth_Basic')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[String]$AdminName,

		# User/handle of the organization
		[Parameter(Mandatory = $true, ParameterSetName='Auth_Basic')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[String[]]$Name
	)
	Begin {
		Write-Debug -Message 'Entered Function: New-GHEOrganization'
		Write-Debug -Message "$($PSCmdlet.ParameterSetName) Parameter Set"
		$BaseUrl = "https://$ComputerName/api/v3"
		Write-Debug -Message "BaseUrl is: $BaseUrl"

		$Header = @{
			"Accept" = "$APIVersionHeader"
		}
		If ($PersonalAccessToken) {
			$Header.Add('Authorization', "token $PersonalAccessToken")
		}

		If ($OneTimePasscode) {
			$Header.Add('X-GitHub-OTP',$OneTimePasscode)
		}
		Write-Debug -Message "Current value of Headers is: $(Out-String -InputObject $Header)"
	}
	Process {
		Foreach ($Handle in $Name) {
			$Body = @{
				'login' = $Handle
				'admin' = $AdminName
				'profile_name' = $DisplayName
			}
			Write-Debug -Message "Request Body: $(Out-String -InputObject $Body)"

			$JSONData = ConvertTo-Json -InputObject $Body
			Write-Debug -Message "JSON data: $JSONData"


			If ($Credential) {
				Write-Debug -Message "Creating new organization using Basic Authentication: $Handle"
				$Result = Invoke-RestMethod -Uri "$BaseUrl/admin/organizations" -Body $JSONData -Headers $Header -Method POST -Authentication Basic -Credential $Credential -SkipCertificateCheck
				Write-Output -InputObject $Result
			}
			ElseIf ($PersonalAccessToken) {
				Write-Debug -Message "Creating new organization using a PAT: $Handle"
				$Result = Invoke-RestMethod -Uri "$BaseUrl/admin/organizations" -Body $JSONData -Headers $Header -Method POST -SkipCertificateCheck
				Write-Output -InputObject $Result
			}
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

		# Custom API Version Header
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $false, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $false, ParameterSetName='GHE_API')]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json',

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory=$false, ParameterSetName='Auth_Basic')]
		[String]$OneTimePasscode,

		# Name/handle of the organization
		[Parameter(Mandatory = $true, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $true, ParameterSetName='GHE_API')]
		[Alias('Org','Organization')]
		[String[]]$Name
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
		If ($PersonalAccessToken) {
			$Header.Add('Authorization', "token $PersonalAccessToken")
		}
		If ($OneTimePasscode) {
			$Header.Add('X-GitHub-OTP',$OneTimePasscode)
		}
		Write-Debug -Message "Current value of Headers is: $(Out-String -InputObject $Header)"
	}
	Process {
		Foreach ($Org in $Name) {
			Write-Debug -Message "Current ParameterSet: $($PSCmdlet.ParameterSetName)"
			If ($PSCmdlet.ParameterSetName -eq 'DotCom_API') {
				If ($Credential) {
					Write-Debug -Message "Querying for organization using basic authentication: $Org"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Org" -Method GET -Headers $Header -Authentication Basic -Credential $Credential -SkipCertificateCheck
					Write-Output -InputObject $Result
				}
				Elseif ($PersonalAccessToken) {
					Write-Debug -Message "Querying for organization using basic authentication: $Org"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Org" -Method GET -Headers $Header -SkipCertificateCheck
					Write-Output -InputObject $Result
				}
			}
			ElseIf ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
				If ($Credential) {
					Write-Debug -Message "Querying for organization using basic authentication: $Org"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Org" -Method GET -Headers $Header -Authentication Basic -Credential $Credential -SkipCertificateCheck
					Write-Output -InputObject $Result
				}
				Elseif ($PersonalAccessToken) {
					Write-Debug -Message "Querying for organization using basic authentication: $Org"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Org" -Method GET -Headers $Header -SkipCertificateCheck
					Write-Output -InputObject $Result
				}
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
	[CmdletBinding(DefaultParameterSetName='Auth_Basic')]
	Param(
		# URL of the API end point
		[Parameter(Mandatory = $true, ParameterSetName='Auth_Basic')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[String]$ComputerName,

		# Personal Access Token for authentication against the GHE API
		[Parameter(Mandatory = $true, ParameterSetName='Auth_Basic')]
		[PSCredential]$Credential,

		# Personal Access Token to authenticate against GitHub.com
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[Alias('PAT')]
		[String]$PersonalAccessToken,

		# Custom API Version Header
		[Parameter(Mandatory = $false, ParameterSetName='Auth_PAT')]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json',

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory=$false, ParameterSetName='Auth_Basic')]
		[String]$OneTimePasscode,

		# Username/login of the user
		[Parameter(Mandatory = $false)]
		[Alias('Handle')]
		[String]$Name,

		# Email address for the invite
		[Parameter(Mandatory = $false)]
		[Alias('Email')]
		[String[]]$EmailAddress
	)
	Begin {
		Write-Debug -Message 'Entered Function: New-GHEUser'
		Write-Debug -Message "$($PSCmdlet.ParameterSetName) Parameter Set"
		$BaseUrl = "https://$ComputerName/api/v3"
		Write-Debug -Message "BaseUrl is: $BaseUrl"

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
		Foreach ($Email in $EmailAddress) {
			$Body = @{
				'login' = $Name
				'email' = $Email
			}
			Write-Debug -Message "Request Body: $(Out-String -InputObject $Body)"

			$JSONData = ConvertTo-Json -InputObject $Body
			Write-Debug -Message "JSON data: $JSONData"

			If ($Credential) {
				Write-Debug -Message "Creating new user using Basic Authentication: $Name"
				$Result = Invoke-RestMethod -Uri "$BaseUrl/admin/users" -Body $JSONData -Headers $Header -Method POST -Authentication Basic -Credential $Credential -SkipCertificateCheck
				Write-Output -InputObject $Result
			}
			ElseIf ($PersonalAccessToken) {
				Write-Debug -Message "Creating new user using a PAT: $Name"
				$Result = Invoke-RestMethod -Uri "$BaseUrl/admin/users" -Body $JSONData -Headers $Header -Method POST -SkipCertificateCheck
				Write-Output -InputObject $Result
			}
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: New-GHEUser'
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

		# Custom API Version Header
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $false, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $false, ParameterSetName='GHE_API')]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json',

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory=$false, ParameterSetName='Auth_Basic')]
		[String]$OneTimePasscode,

		# Fully qualified name of the team
		[Parameter(Mandatory = $true, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $true, ParameterSetName='GHE_API')]
		[Alias('Handle')]
		[String[]]$Name
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
		If ($PersonalAccessToken) {
			$Header.Add('Authorization',"token $PersonalAccessToken")
		}

		If ($OneTimePasscode) {
			$Header.Add('X-GitHub-OTP',$OneTimePasscode)
		}
		Write-Debug -Message "Current value of Headers is: $(Out-String -InputObject $Header)"
	}
	Process {
		Foreach ($Handle in $Name) {
			Write-Debug -Message "Current ParameterSet: $($PSCmdlet.ParameterSetName)"

			If ($PSCmdlet.ParameterSetName -eq 'DotCom_API') {
				If ($Credential) {
					Write-Debug -Message "Querying user $Handle using Basic Authentication"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/users/$Handle" -Headers $Header -Method GET -Authentication Basic -Credential $Credential
					Write-Output -InputObject $Result
				}
				If ($PersonalAccessToken) {
					Write-Debug -Message "Querying user $Handle using a PAT"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/users/$Handle" -Headers $Header -Method GET
					Write-Output -InputObject $Result
				}
			}
			ElseIf ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
				If ($Credential) {
					Write-Debug -Message "Querying user $Handle using Basic Authentication"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/users/$Handle" -Headers $Header -Method GET -Authentication Basic -Credential $Credential -SkipCertificateCheck
					Write-Output -InputObject $Result
				}
				If ($PersonalAccessToken) {
					Write-Debug -Message "Querying user $Handle using a PAT"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/users/$Handle" -Headers $Header -Method GET -SkipCertificateCheck
					Write-Output -InputObject $Result
				}
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
	[CmdletBinding(DefaultParameterSetName='Auth_Basic')]
	Param(
		# URL of the API end point
		[Parameter(Mandatory = $true, ParameterSetName='Auth_Basic')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[String]$ComputerName,

		# Personal Access Token for authentication against the GHE API
		[Parameter(Mandatory = $true, ParameterSetName='Auth_Basic')]
		[PSCredential]$Credential,

		# Personal Access Token to authenticate against GitHub.com
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[Alias('PAT')]
		[String]$PersonalAccessToken,

		# Custom API Version Header
		[Parameter(Mandatory = $false, ParameterSetName='Auth_PAT')]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json',

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory=$false, ParameterSetName='Auth_Basic')]
		[String]$OneTimePasscode,

		# Username/login of the user
		[Parameter(Mandatory=$true)]
		[Alias('Handle')]
		[String[]]$Name
	)
	Begin {
		Write-Debug -Message 'Entered Function: Remove-GHEUser'
		Write-Debug -Message "$($PSCmdlet.ParameterSetName) Parameter Set"

		$BaseUrl = "https://$ComputerName/api/v3"
		Write-Debug -Message "BaseUrl is: $BaseUrl"

		$Header = @{
			"Accept" = "$APIVersionHeader"
		}
		If ($PersonalAccessToken) {
			$Header.Add('Authorization', "token $PersonalAccessToken")
		}

		If ($OneTimePasscode) {
			$Header.Add('X-GitHub-OTP',$OneTimePasscode)
		}
		Write-Debug -Message "Current value of Headers is: $(Out-String -InputObject $Header)"
	}
	Process {
		Foreach ($Handle in $Name) {
			If ($Credential) {
				Write-Debug -Message "Removing user account using basic authentication: $Handle"
				$Result = Invoke-RestMethod -Uri "$BaseUrl/admin/users/$Handle" -Method DELETE -Headers $Header -Credential $Credential -Authentication Basic -SkipCertificateCheck
				Write-Output -InputObject $Result
			}
			If ($PersonalAccessToken) {
				Write-Debug -Message "Removing user account using a PAT: $Handle"
				$Result = Invoke-RestMethod -Uri "$BaseUrl/admin/users/$Handle" -Method DELETE -Headers $Header -SkipCertificateCheck
				Write-Output -InputObject $Result
			}
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
	[CmdletBinding(DefaultParameterSetName='Auth_Basic')]
	Param(
		# URL of the API end point
		[Parameter(Mandatory = $true, ParameterSetName='Auth_Basic')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[String]$ComputerName,

		# Personal Access Token for authentication against the GHE API
		[Parameter(Mandatory = $true, ParameterSetName='Auth_Basic')]
		[PSCredential]$Credential,

		# Personal Access Token to authenticate against GitHub.com
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[Alias('PAT')]
		[String]$PersonalAccessToken,

		# Custom API Version Header
		[Parameter(Mandatory = $false, ParameterSetName='Auth_PAT')]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json',

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory=$false, ParameterSetName='Auth_Basic')]
		[String]$OneTimePasscode,

		# Username/login of the user
		[Parameter(Mandatory=$true)]
		[Alias('Handle')]
		[String[]]$Name
	)
	Begin {
		Write-Debug -Message 'Entered Function: Suspend-GHEUser'
		Write-Debug -Message "$($PSCmdlet.ParameterSetName) Parameter Set"

		$BaseUrl = "https://$ComputerName/api/v3"
		Write-Debug -Message "BaseUrl is: $BaseUrl"

		$Header = @{
			"Accept" = "$APIVersionHeader"
		}
		If ($PersonalAccessToken) {
			$Header.Add('Authorization', "token $PersonalAccessToken")
		}
		If ($OneTimePasscode) {
			$Header.Add('X-GitHub-OTP',$OneTimePasscode)
		}
		Write-Debug -Message "Current value of Headers is: $(Out-String -InputObject $Header)"
	}
	Process {
		Foreach ($Handle in $Name) {
			If ($Credential) {
				Write-Debug -Message "Suspending user account using basic authentication: $Handle"
				$Result = Invoke-RestMethod -Uri "$BaseUrl/users/$Handle/suspended" -Method PUT -Headers $Header -Credential $Credential -Authentication Basic -SkipCertificateCheck
				Write-Output -InputObject $Result
			}
			If ($PersonalAccessToken) {
				Write-Debug -Message "Suspending user account using a PAT: $Handle"
				$Result = Invoke-RestMethod -Uri "$BaseUrl/users/$Handle/suspended" -Method PUT -Headers $Header -SkipCertificateCheck
				Write-Output -InputObject $Result
			}
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Remove-GHEUser'
	}
}
function Resume-GHEUser {
	<#
	.SYNOPSIS
		Resume/unsuspend a user account
	.DESCRIPTION
		This cmdlet resumes/unsuspend a user which was previously suspended/disabled
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
	[CmdletBinding(DefaultParameterSetName='Auth_Basic')]
	Param(
		# URL of the API end point
		[Parameter(Mandatory = $true, ParameterSetName='Auth_Basic')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[String]$ComputerName,

		# Personal Access Token for authentication against the GHE API
		[Parameter(Mandatory = $true, ParameterSetName='Auth_Basic')]
		[PSCredential]$Credential,

		# Personal Access Token to authenticate against GitHub.com
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[Alias('PAT')]
		[String]$PersonalAccessToken,

		# Custom API Version Header
		[Parameter(Mandatory = $false, ParameterSetName='Auth_PAT')]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json',

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory=$false, ParameterSetName='Auth_Basic')]
		[String]$OneTimePasscode,

		# Username/login of the user
		[Parameter(Mandatory=$true)]
		[Alias('Handle')]
		[String[]]$Name
	)
	Begin {
		Write-Debug -Message 'Entered Function: Resume-GHEUser'
		Write-Debug -Message "$($PSCmdlet.ParameterSetName) Parameter Set"

		$BaseUrl = "https://$ComputerName/api/v3"
		Write-Debug -Message "BaseUrl is: $BaseUrl"

		$Header = @{
			"Accept" = "$APIVersionHeader"
		}
		If ($PersonalAccessToken) {
			$Header.Add('Authorization', "token $PersonalAccessToken")
		}
		If ($OneTimePasscode) {
			$Header.Add('X-GitHub-OTP',$OneTimePasscode)
		}
		Write-Debug -Message "Current value of Headers is: $(Out-String -InputObject $Header)"
	}
	Process {
		Foreach ($Handle in $Name) {
			If ($Credential) {
				Write-Debug -Message "Suspending user account using basic authentication: $Handle"
				$Result = Invoke-RestMethod -Uri "$BaseUrl/users/$Handle/suspended" -Method DELETE -Headers $Header -Credential $Credential -Authentication Basic -SkipCertificateCheck
				Write-Output -InputObject $Result
			}
			If ($PersonalAccessToken) {
				Write-Debug -Message "Suspending user account using a PAT: $Handle"
				$Result = Invoke-RestMethod -Uri "$BaseUrl/users/$Handle/suspended" -Method DELETE -Headers $Header -SkipCertificateCheck
				Write-Output -InputObject $Result
			}
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
	[CmdletBinding(DefaultParameterSetName='Auth_Basic')]
	Param(
		# URL of the API end point
		[Parameter(Mandatory = $true, ParameterSetName='Auth_Basic')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[String]$ComputerName,

		# Personal Access Token for authentication against the GHE API
		[Parameter(Mandatory = $true, ParameterSetName='Auth_Basic')]
		[PSCredential]$Credential,

		# Personal Access Token to authenticate against GitHub.com
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[Alias('PAT')]
		[String]$PersonalAccessToken,

		# Custom API Version Header
		[Parameter(Mandatory = $false, ParameterSetName='Auth_PAT')]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json',

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory=$false, ParameterSetName='Auth_Basic')]
		[String]$OneTimePasscode,

		# Username/login of the user
		[Parameter(Mandatory=$true)]
		[Alias('Handle')]
		[String]$Name,

		# New name of the user to be updated
		[Parameter(Mandatory=$true)]
		[String]$NewName
	)
	Begin {
		Write-Debug -Message 'Entered Function: Rename-GHEUser'
		Write-Debug -Message "$($PSCmdlet.ParameterSetName) Parameter Set"

		$BaseUrl = "https://$ComputerName/api/v3"
		Write-Debug -Message "BaseUrl is: $BaseUrl"

		$Header = @{
			"Accept" = "$APIVersionHeader"
		}
		If ($PersonalAccessToken) {
			$Header.Add('Authorization', "token $PersonalAccessToken")
		}
		If ($OneTimePasscode) {
			$Header.Add('X-GitHub-OTP',$OneTimePasscode)
		}
		Write-Debug -Message "Current value of Headers is: $(Out-String -InputObject $Header)"
	}
	Process {
		$Body = @{
			'login' = $NewName
		}
		Write-Debug -Message "Request Body: $(Out-String -InputObject $Body)"

		$JSONData = ConvertTo-Json -InputObject $Body
		Write-Debug -Message "JSON data: $(Out-String -InputObject $JSONData)"

		If ($Credential) {
			Write-Debug -Message "Renaming user account using basic authentication: $Name"
			$Result = Invoke-RestMethod -Uri "$BaseUrl/admin/users/$Name" -Method PATCH -Headers $Header -Body $JSONData -Credential $Credential -Authentication Basic -SkipCertificateCheck
			Write-Output -InputObject $Result
		}
		If ($PersonalAccessToken) {
			Write-Debug -Message "Renaming user account using a PAT: $Name"
			$Result = Invoke-RestMethod -Uri "$BaseUrl/admin/users/$Name" -Method PATCH -Headers $Header -Body $JSONData -SkipCertificateCheck
			Write-Output -InputObject $Result
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Rename-GHEUser'
	}
}
function Get-GHTeam {
	<#
	.SYNOPSIS
		Get information on a team
	.DESCRIPTION
		This cmdlet retrieves information on a team
	.EXAMPLE
		PS ~/ Get-GHTeam -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Organization 'MyOrg' -Handle 'Development'
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you retrieves information on the team named Development
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

		# Custom API Version Header
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $false, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $false, ParameterSetName='GHE_API')]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json',

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory=$false, ParameterSetName='Auth_Basic')]
		[String]$OneTimePasscode,

		# Fully qualified name of the team
		[Parameter(Mandatory = $true, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $true, ParameterSetName='GHE_API')]
		[String[]]$Name
	)
	Begin {
		Write-Debug -Message "Entered function: Get-GHTeam"

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
		Foreach ($Handle in $Name) {
			Write-Debug -Message "Current ParameterSet: $($PSCmdlet.ParameterSetName)"
			$TeamResolvedName = Resolve-GHRepoName -Repository $Handle
			Write-Debug -Message "Split $Handle string to $($TeamResolvedName.Owner) & $($TeamResolvedName.Name)"

			$FullList = @{}

			If ($PSCmdlet.ParameterSetName -eq 'DotCom_API') {
				If ($Credential) {
					Write-Debug -Message "Querying list of all teams inside the $($TeamResolvedName.Owner) org using Basic Authentication"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$($TeamResolvedName.Owner)/teams" -Headers $Header -Method GET -Authentication Basic -Credential $Credential
					# This is ugly and we should change this
					Foreach ($PSItem in $Result) {
						Foreach ($i in $PSItem) {
							$FullList[$i.name] = $i.id
						}
					}

					If ($FullList.ContainsKey($TeamResolvedName.Name)) {
						Write-Debug -Message "Located team $Handle with the id of: $($FullList[$TeamResolvedName.Name])"

						$Result = Invoke-RestMethod -Uri "$BaseUrl/teams/$($FullList[$TeamResolvedName.Name])" -Headers $Header -Credential $Credential -Authentication Basic -Method GET
						Write-Output $Result
					}
				}
				ElseIf ($PersonalAccessToken) {
					Write-Debug -Message "Querying list of all teams inside the $($TeamResolvedName.Owner) org using a PAT"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$($TeamResolvedName.Owner)/teams" -Headers $Header -Method GET -FollowRelLink
					Write-Debug -Message "Result of REST request: $(Out-String -InputObject $Result)"
					# This is ugly and we should change this
					Foreach ($PSItem in $Result) {
						Foreach ($i in $PSItem) {
							$FullList[$i.name] = $i.id
						}
					}

					If ($FullList.ContainsKey($TeamResolvedName.Name)) {
						Write-Debug -Message "Located team $Handle with the id of: $($FullList[$TeamResolvedName.Name])"

						$Result = Invoke-RestMethod -Uri "$BaseUrl/teams/$($FullList[$TeamResolvedName.Name])" -Headers $Header -Method GET
						Write-Output $Result
					}
				}
			}
			ElseIf ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
				If ($Credential) {
					Write-Debug -Message "Querying list of all teams inside the $($TeamResolvedName.Owner) org using Basic Authentication"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$($TeamResolvedName.Owner)/teams" -Headers $Header -Method GET -Authentication Basic -Credential $Credential -SkipCertificateCheck
					# This is ugly and we should change this
					Foreach ($PSItem in $Result) {
						Foreach ($i in $PSItem) {
							$FullList[$i.name] = $i.id
						}
					}

					If ($FullList.ContainsKey($TeamResolvedName.Name)) {
						Write-Debug -Message "Located team $Handle with the id of: $($FullList[$TeamResolvedName.Name])"

						$Result = Invoke-RestMethod -Uri "$BaseUrl/teams/$($FullList[$TeamResolvedName.Name])" -Headers $Header -Credential $Credential -Authentication Basic -Method GET -SkipCertificateCheck
						Write-Output $Result
					}
				}
				ElseIf ($PersonalAccessToken) {
					Write-Debug -Message "Querying list of all teams inside the $($TeamResolvedName.Owner) org using a PAT"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$($TeamResolvedName.Owner)/teams" -Headers $Header -Method GET -SkipCertificateCheck
					# This is ugly and we should change this
					Foreach ($PSItem in $Result) {
						Foreach ($i in $PSItem) {
							$FullList[$i.name] = $i.id
						}
					}

					If ($FullList.ContainsKey($TeamResolvedName.Name)) {
						Write-Debug -Message "Located team $Handle with the id of: $($FullList[$TeamResolvedName.Name])"

						$Result = Invoke-RestMethod -Uri "$BaseUrl/teams/$($FullList[$TeamResolvedName.Name])" -Headers $Header -Method GET -SkipCertificateCheck
						Write-Output $Result
					}
				}
			}
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Get-GHTeam'
	}
}
function New-GHTeam {
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

		# Custom API Version Header
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $false, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $false, ParameterSetName='GHE_API')]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json',

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $false, ParameterSetName='Auth_Basic')]
		[String]$OneTimePasscode,

		# User/handle of the organization
		[Parameter(Mandatory = $true)]
		[String]$Name,

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
		Write-Debug -Message 'Entered Function: New-GHTeam'

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
		Foreach ($Handle in $Name) {
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
			If ($PSCmdlet.ParameterSetName -eq 'DotCom_API') {
				If ($Credential) {
					Write-Debug -Message "Creating team $Handle with Basic Authentication using endpoint: $BaseUrl/orgs/$Organization/teams"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Organization/teams" -Headers $Header -Body $JSONData -Method POST -Authentication Basic -Credential $Credential
					Write-Debug -Message "Result of REST request: $(Out-String -InputObject $Result)"
				}
				If ($PersonalAccessToken) {
					Write-Debug -Message "Creating team $Handle with a PAT using endpoint: $BaseUrl/orgs/$Organization/teams"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Organization/teams" -Headers $Header -Body $JSONData -Method POST
					Write-Debug -Message "Result of REST request: $(Out-String -InputObject $Result)"
				}
			}
			If ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
				If ($Credential) {
					Write-Debug -Message "Creating team $Handle with Basic Authentication using endpoint: $BaseUrl/orgs/$Organization/teams"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Organization/teams" -Headers $Header -Body $JSONData -Method POST -Authentication Basic -Credential $Credential -SkipCertificateCheck
					Write-Debug -Message "Result of REST request: $(Out-String -InputObject $Result)"
				}
				If ($PersonalAccessToken) {
					Write-Debug -Message "Creating team $Handle with a PAT using endpoint: $BaseUrl/orgs/$Organization/teams"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Organization/teams" -Headers $Header -Body $JSONData -Method POST -SkipCertificateCheck
					Write-Debug -Message "Result of REST request: $(Out-String -InputObject $Result)"
				}
			}
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: New-GHTeam'
	}
}
function Remove-GHTeam {
	<#
	.SYNOPSIS
		Removes a team
	.DESCRIPTION
		This cmdlet removes/deletes a team
	.EXAMPLE
		PS ~/ Remove-GHTeam -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle 'FrontEndTeam' -Organization Development
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then removes the team FrontEndTeam
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

		# Custom API Version Header
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $false, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $false, ParameterSetName='GHE_API')]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json',

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $false, ParameterSetName='Auth_Basic')]
		[String]$OneTimePasscode,

		[Parameter(Mandatory = $true, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $true, ParameterSetName='GHE_API')]
		[String[]]$Name
	)
	Begin {
		Write-Debug -Message "Entered function: Remove-GHTeam"

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
		Foreach ($Handle in $Name) {
			$TeamResolvedName = Resolve-GHRepoName -Repository $Handle
			Write-Debug -Message "Split $Handle string to $($TeamResolvedName.Owner) & $($TeamResolvedName.Name)"

			$FullList = @{}

			If ($PSCmdlet.ParameterSetName -eq 'DotCom_API') {
				If ($Credential) {
					Write-Debug -Message "Retrieving list of teams with Basic Authentication using endpoint: $BaseUrl/orgs/$($TeamResolvedName.Owner)/teams"
					$TeamsResult = Invoke-RestMethod -Uri "$BaseUrl/orgs/$($TeamResolvedName.Owner)/teams" -Method GET -Headers $Header -Authentication Basic -Credential $Credential -SkipCertificateCheck

					Foreach ($PSItem in $TeamsResult) {
						Foreach ($i in $PSItem) {
							$FullList[$i.name] = $i.id
						}
					}

					If ($FullList.ContainsKey($TeamResolvedName.Name)) {
						Write-Debug -Message "Located team $Handle with the id of: $($FullList[$TeamResolvedName.Name])"

						$Result = Invoke-RestMethod -Uri "$BaseUrl/teams/$($FullList[$TeamResolvedName.Name])" -Headers $Header -Credential $Credential -Authentication Basic -Method DELETE
						Write-Output $Result
					}
				}
				}
				If ($PersonalAccessToken) {
					Write-Debug -Message "Retrieving list of teams with a PAT using endpoint: $BaseUrl/orgs/$($TeamResolvedName.Owner)/teams"
					$TeamsResult = Invoke-RestMethod -Uri "$BaseUrl/orgs/$($TeamResolvedName.Owner)/teams" -Method GET -Headers $Header -Authentication Basic -Credential $Credential -SkipCertificateCheck

					Foreach ($PSItem in $TeamsResult) {
						Foreach ($i in $PSItem) {
							$FullList[$i.name] = $i.id
						}
					}

					If ($FullList.ContainsKey($TeamResolvedName.Name)) {
						Write-Debug -Message "Located team $Handle with the id of: $($FullList[$TeamResolvedName.Name])"

						$Result = Invoke-RestMethod -Uri "$BaseUrl/teams/$($FullList[$TeamResolvedName.Name])" -Headers $Header -Credential $Credential -Authentication Basic -Method DELETE
						Write-Output $Result
					}
				}
			}
			If ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
				If ($Credential) {
					Write-Debug -Message "Retrieving list of teams with Basic Authentication using endpoint: $BaseUrl/orgs/$($TeamResolvedName.Owner)/teams"
					$TeamsResult = Invoke-RestMethod -Uri "$BaseUrl/orgs/$($TeamResolvedName.Owner)/teams" -Method GET -Headers $Header -Authentication Basic -Credential $Credential -SkipCertificateCheck

					Foreach ($PSItem in $TeamsResult) {
						Foreach ($i in $PSItem) {
							$FullList[$i.name] = $i.id
						}
					}

					If ($FullList.ContainsKey($TeamResolvedName.Name)) {
						Write-Debug -Message "Located team $Handle with the id of: $($FullList[$TeamResolvedName.Name])"

						$Result = Invoke-RestMethod -Uri "$BaseUrl/teams/$($FullList[$TeamResolvedName.Name])" -Headers $Header -Credential $Credential -Authentication Basic -Method DELETE
						Write-Output $Result
					}
				}
				If ($PersonalAccessToken) {
					Write-Debug -Message "Retrieving list of teams with a PAT using endpoint: $BaseUrl/orgs/$($TeamResolvedName.Owner)/teams"
					$TeamsResult = Invoke-RestMethod -Uri "$BaseUrl/orgs/$($TeamResolvedName.Owner)/teams" -Method GET -Headers $Header -Authentication Basic -Credential $Credential -SkipCertificateCheck

					Foreach ($PSItem in $TeamsResult) {
						Foreach ($i in $PSItem) {
							$FullList[$i.name] = $i.id
						}
					}

					If ($FullList.ContainsKey($TeamResolvedName.Name)) {
						Write-Debug -Message "Located team $Handle with the id of: $($FullList[$TeamResolvedName.Name])"

						$Result = Invoke-RestMethod -Uri "$BaseUrl/teams/$($FullList[$TeamResolvedName.Name])" -Headers $Header -Credential $Credential -Authentication Basic -Method DELETE
						Write-Output $Result
					}
				}
			}
		}

	End {
		Write-Debug -Message 'Exiting function: Remove-GHTeam'
	}
}
function New-GHRepo {
	<#
	.SYNOPSIS
		Creates a new Repository
	.DESCRIPTION
		This cmdlet creates a new repository
	.EXAMPLE
		PS ~/ New-GHTeam -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Name MyNewRepo -Description 'New repo for my project!' -HomePage 'https://myprojectsite.com/' -Organization Development -Private -AutoInit -LicenseTemplate 'mit'
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then creates a new Repository named MyNewRepo that has a homepage value of https://myprojectsite.com/ along with associating it within the Development organiztion, initializing it, and restricting it to be private while also associating the MIT open-source license to it.
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

		# Custom API Version Header
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $false, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $false, ParameterSetName='GHE_API')]
		[String]$APIVersionHeader = 'application/vnd.github.v3+json',

		# One-Time Passcode for two-factor authentication
		[Parameter(Mandatory = $false, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $false, ParameterSetName='Auth_Basic')]
		[String]$OneTimePasscode,

		[Parameter(Mandatory = $true, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $true, ParameterSetName='GHE_API')]
		[String[]]$Name,

		# Description for the repository
		[Parameter(Mandatory = $false)]
		[String]$Description,

		# URL with more information about the repository
		[Parameter(Mandatory = $false)]
		[String]$HomePage,

		# Organization owner of the repository
		[Parameter(Mandatory = $false)]
		[String]$Organization,

		# Switch to create a private repository
		[Parameter(Mandatory = $false)]
		[Switch]$Private,

		# Switch to turn off issue tracking
		[Parameter(Mandatory = $false)]
		[Switch]$DisableIssues,

		# Switch to turn off project boards
		[Parameter(Mandatory = $false)]
		[Switch]$DisableProjects,

		# Switch to turn off wiki support
		[Parameter(Mandatory = $false)]
		[Switch]$DisableWiki,

		# The ID of the team that will have access to this repository
		[Parameter(Mandatory = $false)]
		[Int]$TeamId,

		# Switch to automatically initialize the repo with an emtpy README file and commit
		[Parameter(Mandatory = $false)]
		[Switch]$AutoInit,

		# The language or platform of the template to apply
		[Parameter(Mandatory = $false)]
		[String]$GitIgnoreTemplate,

		# The license template for the repository
		[Parameter(Mandatory = $false)]
		[String]$LicenseTemplate,

		# Switch to disable squash merging pull requests
		[Parameter(Mandatory = $false)]
		[Switch]$DisableSquash,

		# Switch to disable merge commits/pull requests
		[Parameter(Mandatory = $false)]
		[Switch]$DisableMerge,

		# Switch to disable rebase merge commits/pull requests
		[Parameter(Mandatory = $false)]
		[Switch]$DisableRebase
	)
	Begin {
		Write-Debug -Message "Entered function: New-GHRepo"

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

			$JSONData = ConvertTo-Json -InputObject $Body
			Write-Debug -Message "JSON data: $JSONData"

			If ($PSCmdlet.ParameterSetName -eq 'DotCom_API') {
				If ($Credential) {
					If ([String]::IsNullOrEmpty($Organization)) {
						Write-Debug -Message "Organization is not defined, creating a User repo with Basic Authentication using endpoint: $BaseUrl/user/repos"
						$Result = Invoke-RestMethod -Method POST -Uri "$BaseUrl/user/repos" -Headers $Header -Body $JSONData -Authentication Basic -Credential $Credential
						Write-Output -InputObject $Result
					}
					Else {
						Write-Debug -Message "Organization is defined, creating an Organization repo with Basic Authentication using endpoint: $BaseUrl/orgs/$Organization/repos"
						$Result = Invoke-RestMethod -Method POST -Uri "$BaseUrl/orgs/$Organization/repos" -Headers $Header -Body $JSONData -Authentication Basic -Credential $Credential
						Write-Output -InputObject $Result
					}
				}
				If ($PersonalAccessToken) {
					If ([String]::IsNullOrEmpty($Organization)) {
						Write-Debug -Message "Organization is not defined, creating a User repo with a PAT using endpoint: $BaseUrl/user/repos"
						$Result = Invoke-RestMethod -Method POST -Uri "$BaseUrl/user/repos" -Headers $Header -Body $JSONData
						Write-Output -InputObject $Result
					}
					Else {
						Write-Debug -Message "Organization is defined, creating an Organization repo with a PAT using endpoint: $BaseUrl/orgs/$Organization/repos"
						$Result = Invoke-RestMethod -Method POST -Uri "$BaseUrl/orgs/$Organization/repos" -Headers $Header -Body $JSONData
						Write-Output -InputObject $Result
					}
				}
			}
			If ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
				If ($Credential) {
					If ([String]::IsNullOrEmpty($Organization)) {
						Write-Debug -Message "Organization is not defined, creating a User repo with Basic Authentication using endpoint: $BaseUrl/user/repos"
						$Result = Invoke-RestMethod -Method POST -Uri "$BaseUrl/user/repos" -Headers $Header -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
						Write-Output -InputObject $Result
					}
					Else {
						Write-Debug -Message "Organization is defined, creating an Organization repo with Basic Authentication using endpoint: $BaseUrl/orgs/$Organization/repos"
						$Result = Invoke-RestMethod -Method POST -Uri "$BaseUrl/orgs/$Organization/repos" -Headers $Header -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
						Write-Output -InputObject $Result
					}
				}
				If ($PersonalAccessToken) {
					If ([String]::IsNullOrEmpty($Organization)) {
						Write-Debug -Message "Organization is not defined, creating a User repo with a PAT using endpoint: $BaseUrl/user/repos"
						$Result = Invoke-RestMethod -Method POST -Uri "$BaseUrl/user/repos" -Headers $Header -Body $JSONData -SkipCertificateCheck
						Write-Output -InputObject $Result
					}
					Else {
						Write-Debug -Message "Organization is defined, creating an Organization repo with a PAT using endpoint: $BaseUrl/orgs/$Organization/repos"
						$Result = Invoke-RestMethod -Method POST -Uri "$BaseUrl/orgs/$Organization/repos" -Headers $Header -Body $JSONData -SkipCertificateCheck
						Write-Output -InputObject $Result
					}
				}
			}
		}
	}
	End {
		Write-Debug -Message "Exited function: New-GHRepo"
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
function Remove-GHRepo {
	<#
	.SYNOPSIS
		Removes a repository
	.DESCRIPTION
		This cmdlet removes/deletes a repository
	.EXAMPLE
		PS ~/ Remove-GHRepo -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Name MyNewRepo -Owner MonaLisa
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and removes the repository named MyNewRepo which is owned by MonaLisa.
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
		[Alias('OTP')]
		[String]$OneTimePasscode
	)
	Begin {
		Write-Debug -Message "Entered function: Remove-GHRepo"

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
		Foreach ($Repo in $Name) {
			Write-Debug -Message "Current ParameterSet: $($PSCmdlet.ParameterSetName)"
			$RepoResolvedName = Resolve-GHRepoName -Repository $Repo
			Write-Debug -Message "Split $Repo string to $($RepoResolvedName.Owner) & $($RepoResolvedName.Name)"
			If ($PSCmdlet.ParameterSetName -eq 'DotCom_API') {
				If ($Credential) {
					Write-Debug -Message "Removing repository using Basic Authentication: $Repo"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)" -Headers $Header -Method DELETE -Authentication Basic -Credential $Credential
					Write-Output -InputObject $Result
				}
				ElseIf ($PersonalAccessToken) {
					Write-Debug -Message "Removing repository using a PAT: $Repo"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)" -Headers $Header -Method DELETE
					Write-Output -InputObject $Result
				}
			}
			ElseIf ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
				If ($Credential) {
					Write-Debug -Message "Removing repository using Basic Authentication: $Repo"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)" -Headers $Header -Method DELETE -Authentication Basic -Credential $Credential -SkipCertificateCheck
					Write-Output -InputObject $Result
				}
				ElseIf ($PersonalAccessToken) {
					Write-Debug -Message "Removing repository using a PAT: $Repo"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)" -Headers $Header -Method DELETE -SkipCertificateCheck
					Write-Output -InputObject $Result
				}
			}
		}
	}
	End {
		Write-Debug -Message 'Exited Function: Remove-GHRepo'
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
function Add-GHOrgMembership {
	<#
	.SYNOPSIS
		Add a user to an organization
	.DESCRIPTION
		This cmdlet accepts a username/handle and adds it to the organization membership
	.EXAMPLE
		PS ~/ Add-GHOrgMembership -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle MonaLisa -Organization Development -Role member
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then adds MonaLisa to the Development organization
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

		# Username/login for the user
		[Parameter(Mandatory = $true)]
		[String[]]$User,

		# Organization handle that the member will join
		[Parameter(Mandatory = $true)]
		[Alias('Org')]
		[String]$Organization,

		# Role to give the user in the organization (default is 'member')
		[Parameter(Mandatory = $false)]
		[String]$Role = 'member'
	)
	Begin {
		Write-Debug -Message "Entered function: Add-GHOrgMembership"

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
		Foreach ($Name in $User) {
			Write-Debug -Message "Current ParameterSet: $($PSCmdlet.ParameterSetName)"

			$QualifiedUrl = "https://$ComputerName/api/v3/orgs/$Organization/memberships/$Name"
			Write-Debug -Message "Qualified URL is: $QualifiedUrl"

			$Body = @{
				'role' = $Role
			}
			Write-Debug -Message "Request Body: $(Out-String -InputObject $Body)"

			$JSONData = ConvertTo-Json -InputObject $Body
			Write-Debug -Message "JSON data: $(Out-String -InputObject $JSONData)"

			If ($PSCmdlet.ParameterSetName -eq 'DotCom_API') {
				If ($Credential) {
					Write-Debug -Message "Adding user using Basic Authentication using endpoint: $BaseUrl/orgs/$Organization/memberships/$Name"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Organization/memberships/$Name" -Method PUT -Headers $Header -Body $JSONData -Authentication Basic -Credential $Credential
					Write-Debug -Message "Result of REST request: $(Out-String -InputObject $Result)"
				}
				ElseIf ($PersonalAccessToken) {
					Write-Debug -Message "Adding user using PAT using endpoint: $BaseUrl/orgs/$Organization/memberships/$Name"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Organization/memberships/$Name" -Method PUT -Headers $Header -Body $JSONData
					Write-Debug -Message "Result of REST request: $(Out-String -InputObject $Result)"
				}
			}
			If ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
				If ($Credential) {
					Write-Debug -Message "Adding user using Basic Authentication using endpoint: $BaseUrl/orgs/$Organization/memberships/$Name"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Organization/memberships/$Name" -Method PUT -Headers $Header -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
					Write-Output -InputObject $Result
				}
				ElseIf ($PersonalAccessToken) {
					Write-Debug -Message "Adding user using PAT using endpoint: $BaseUrl/orgs/$Organization/memberships/$Name"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Organization/memberships/$Name" -Method PUT -Headers $Header -Body $JSONData -SkipCertificateCheck
					Write-Output -InputObject $Result
				}
			}
		}
	}
	End {
		Write-Debug -Message 'Exiting function: Add-GHOrgMembership'
	}
}
function Remove-GHOrgMembership {
	<#
	.SYNOPSIS
		Remove a user to an organization
	.DESCRIPTION
		This cmdlet accepts a username/handle and removes it from the organization membership
	.EXAMPLE
		PS ~/ Remove-GHOrgMembership -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -Handle MonaLisa -Organization Development
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then removes MonaLisa from the Development organization
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

		# Username/login for the user
		[Parameter(Mandatory = $true)]
		[String[]]$User,

		# Name of the organization to remove users from
		[Parameter(Mandatory = $true)]
		[Alias("Org")]
		[String]$Organization
	)
	Begin {
		Write-Debug -Message 'Entered function: Remove-GHOrgMembership'

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
		Foreach ($Name in $User) {
			Write-Debug -Message "Current ParameterSet: $($PSCmdlet.ParameterSetName)"

			If ($PSCmdlet.ParameterSetName -eq 'DotCom_API') {
				If ($Credential) {
					Write-Debug -Message "Removing user using Basic Authentication using endpoint: $BaseUrl/orgs/$Organization/memberships/$Name"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Organization/memberships/$Name" -Method DELETE -Headers $Header -Authentication Basic -Credential $Credential
					Write-Debug -Message "Result of REST request: $(Out-String -InputObject $Result)"
				}
				ElseIf ($PersonalAccessToken) {
					Write-Debug -Message "Removing user using PAT using endpoint: $BaseUrl/orgs/$Organization/memberships/$Name"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Organization/memberships/$Name" -Method DELETE -Headers $Header -Body $JSONData -Method POST
					Write-Debug -Message "Result of REST request: $(Out-String -InputObject $Result)"
				}
			}
			If ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
				If ($Credential) {
					Write-Debug -Message "Removing user using Basic Authentication using endpoint: $BaseUrl/orgs/$Organization/memberships/$Name"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Organization/memberships/$Name" -Method DELETE -Headers $Header -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
					Write-Output -InputObject $Result
				}
				ElseIf ($PersonalAccessToken) {
					Write-Debug -Message "Removing user using PAT using endpoint: $BaseUrl/orgs/$Organization/memberships/$Name"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/orgs/$Organization/memberships/$Name" -Method DELETE -Headers $Header -Body $JSONData -SkipCertificateCheck
					Write-Output -InputObject $Result
				}
			}
		}
	}
	End {
		Write-Debug -Message 'Exiting Function: Remove-GHOrgMembership'
	}
}
function Add-GHTeamMembership {
	<#
	.SYNOPSIS
		Add a user to a team
	.DESCRIPTION
		This cmdlet accepts a username/handle and adds it to a team
	.EXAMPLE
		PS ~/ Add-GHTeamMembership -ComputerName myGHEInstance.myhost.com -Credential (Get-Credential) -UserHandle MonaLisa -TeamHandle FrontEndTeam -Role member
		This command connects to the myGHEInstance.myhost.com instance and prompts for credentials, which then authenticates you and then adds MonaLisa to the FrontEndTeam team.
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

		# Username/login for the team
		[Parameter(Mandatory = $true)]
		[String]$Team,

		# Username/login for the user
		[Parameter(Mandatory = $true)]
		[String[]]$User,

		# The role that the user will have on the specified team
		[Parameter(Mandatory = $true)]
		[String]$Role
	)
	Begin {
		Write-Debug -Message 'Entered Function: Add-GHTeamMembership'

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

		$ResolvedTeamName = Resolve-GHRepoName -Repository $Team
		Write-Debug -Message "Split $Team string to $($ResolvedTeamName.Owner) & $($ResolvedTeamName.Name)"
	}
	Process {
		Foreach ($Name in $User) {
			Write-Debug -Message "Current ParameterSet: $($PSCmdlet.ParameterSetName)"

			$RequestBody = @{
				'role' = $Role
			}
			Write-Debug -Message "Request Body: $(Out-String -InputObject $RequestBody)"

			$JSONData = ConvertTo-Json -InputObject $RequestBody
			Write-Debug -Message "JSON data: $(Out-String -InputObject $JSONData)"

			If ($PSCmdlet.ParameterSetName -eq 'DotCom_API') {
				If ($Credential) {
					Write-Debug -Message "Querying team object: $Team"
					$TeamObject = Get-GHTeam -ComputerName $ComputerName -Credential $Credential -Name $Team

					Write-Debug -Message "Adding user using Basic Authentication using endpoint: $BaseUrl/teams/$Team/memberships/$Name"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/teams/$Team/memberships/$Name" -Headers $Header -Body $JSONData -Method POST -Authentication Basic -Credential $Credential
					Write-Debug -Message "Result of REST request: $(Out-String -InputObject $Result)"
				}
				ElseIf ($PersonalAccessToken) {
					Write-Debug -Message "Querying team object: $Team"
					$TeamObject = Get-GHTeam -ComputerName $ComputerName -PersonalAccessToken $PersonalAccessToken -Name $Team

					Write-Debug -Message "Adding user using a PAT using endpoint: $BaseUrl/teams/$Team/memberships/$Name"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/teams/$Team/memberships/$Name" -Headers $Header -Body $JSONData -Method POST
					Write-Debug -Message "Result of REST request: $(Out-String -InputObject $Result)"
				}
			}
			If ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
				If ($Credential) {
					Write-Debug -Message "Querying team object: $Team"
					$TeamObject = Get-GHTeam -ComputerName $ComputerName -Credential $Credential -Name $Team

					Write-Debug -Message "Adding user to team using endpoint: $BaseUrl/teams/$($TeamObject.id)/memberships/$Name"
					$Result = Invoke-RestMethod -Method PUT -Uri "$BaseUrl/teams/$($TeamObject.id)/memberships/$Name" -Headers $Header -Body $JSONData -Authentication Basic -Credential $Credential -SkipCertificateCheck
					Write-Output -InputObject $Result
				}
				ElseIf ($PersonalAccessToken) {
					Write-Debug -Message "Querying team object: $Team"
					$TeamObject = Get-GHTeam -ComputerName $ComputerName -PersonalAccessToken $PersonalAccessToken -Name $Team

					Write-Debug -Message "Adding user to team using endpoint: $BaseUrl/teams/$($TeamObject.id)/memberships/$Name"
					$Result = Invoke-RestMethod -Method PUT -Uri "$BaseUrl/teams/$($TeamObject.id)/memberships/$Name" -Headers $Header -Body $JSONData -SkipCertificateCheck
					Write-Output -InputObject $Result
				}
			}
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

		# The fully qualified repository name
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
	[CmdletBinding(DefaultParameterSetName='DotCom_API')]
	Param(
		# URL of the API end point
		[Parameter(Mandatory = $false, ParameterSetName='GHE_API')]
		[String]$ComputerName,

		# Credential object for authentication against the GH API
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
		[String]$APIVersionHeader = 'application/vnd.github.symmetra-preview+json',

		# The fully qualified repository name
		[Parameter(Mandatory = $true, ParameterSetName='DotCom_API')]
		[Parameter(Mandatory = $true, ParameterSetName='Auth_PAT')]
		[Parameter(Mandatory = $true, ParameterSetName='GHE_API')]
		[String]$RepoName,

		# ID of the issue to retrieve
		[Parameter(Mandatory = $true)]
		[String[]]$Id
	)
	Begin {
		Write-Debug -Message 'Entered Function: Get-GHIssue'

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
		Foreach ($Issue in $Id) {
			Write-Debug -Message "Current ParameterSet: $($PSCmdlet.ParameterSetName)"
			$RepoResolvedName = Resolve-GHRepoName -Repository $RepoName
			Write-Debug -Message "Split $RepoName string to $($RepoResolvedName.Owner) & $($RepoResolvedName.Name)"

			If ($PSCmdlet.ParameterSetName -eq 'DotCom_API') {
				If ($Credential) {
					Write-Debug -Message "Retrieving issue using Basic Authentication to endpoint: $BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues/$Issue"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues/$Issue" -Headers $Header -Method GET -Authentication Basic -Credential $Credential
					Write-Debug -Message "Result of REST request for issue: $(Out-String -InputObject $Result)"
					Write-Output -InputObject $Result
				}
				ElseIf ($PersonalAccessToken) {
					Write-Debug -Message "Retrieving issue using a PAT to endpoint: $BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues/$Issue"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues/$Issue" -Headers $Header -Method GET
					Write-Debug -Message "Result of REST request for issue: $(Out-String -InputObject $Result)"
					Write-Output -InputObject $Result
				}
			}
			If ($PSCmdlet.ParameterSetName -eq 'GHE_API') {
				If ($Credential) {
					Write-Debug -Message "Retrieving issue using Basic authentication to endpoint: $BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues/$Issue"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues/$Issue" -Headers $Header -Method GET -Authentication Basic -Credential $Credential -SkipCertificateCheck
					Write-Debug -Message "Result of REST request for issue: $(Out-String -InputObject $Result)"
					Write-Output -InputObject $Result
				}
				ElseIf ($PersonalAccessToken) {
					Write-Debug -Message "Retrieving issue using a PAT to endpoint: $BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues/$Issue"
					$Result = Invoke-RestMethod -Uri "$BaseUrl/repos/$($RepoResolvedName.Owner)/$($RepoResolvedName.Name)/issues/$Issue" -Headers $Header -Method GET -SkipCertificateCheck
					Write-Debug -Message "Result of REST request for issue: $(Out-String -InputObject $Result)"
					Write-Output -InputObject $Result
				}
			}
		}
	}
	End {
		Write-Debug -Message 'Exited Function: Get-GHIssue'
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