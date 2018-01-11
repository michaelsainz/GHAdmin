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
        [String]$MgmtPassword
    )
    Begin {
        Write-Debug -Message 'Entered Function: Invoke-GHEInitialConfiguration'

        $QualifiedUrl = "https://$ComputerName/setup/api/start"
        Write-Debug -Message "Qualified URL is: $QualifiedUrl"

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
        curl -k -L -X POST $QualifiedUrl -F license=@$LicenseFile -F "password=$MgmtPassword"
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

        # Personal Access Token for authentication against the GHE API
        [Parameter(Mandatory = $true)]
        [String]$AuthToken,

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
        Write-Debug -Message 'Entered Function: Create-GHEOrganization'

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
            Invoke-RestMethod -Method POST -Uri $QualifiedUrl -Headers $Headers -Body $JSONData -SkipCertificateCheck
        }
    }
    End {
        Write-Debug -Message 'Exiting Function: Create-GHEOrganization'
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
            Invoke-RestMethod -Method POST -Uri $QualifiedUrl -Headers $Headers -Body $JSONData -SkipCertificateCheck
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
            Invoke-RestMethod -Method POST -Uri $QualifiedUrl -Headers $Headers -Body $JSONData -SkipCertificateCheck
        }
    }
    End {
        Write-Debug -Message 'Exiting Function: Create-GHETeam'
    }
}