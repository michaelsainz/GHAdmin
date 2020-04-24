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
