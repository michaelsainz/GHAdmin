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
