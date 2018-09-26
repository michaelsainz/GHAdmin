
function Resolve-GHRepoName {
    <#
	.SYNOPSIS
		Short description
	.DESCRIPTION
		Long description
	.EXAMPLE
		Example of how to use this cmdlet
	.EXAMPLE
		Another example of how to use this cmdlet
	.INPUTS
		Inputs to this cmdlet (if any)
	.OUTPUTS
		Output from this cmdlet (if any)
	.NOTES
		General notes
	.COMPONENT
		The component this cmdlet belongs to
	.ROLE
		The role this cmdlet belongs to
	.FUNCTIONALITY
		The functionality that best describes this cmdlet
	#>
    [CmdletBinding()]
    Param (
        # Specifies the string which contains an owner name and a repo name
        [Parameter(Mandatory = $true)]
        [Alias('Repo')]
        [String[]]$Repository
    )

    Begin {
        Write-Debug -Message 'Entered function: Resolve-GHRepoName'
    }

    Process {
        Foreach ($Repo in $Repository) {
            Write-Debug -Message "Determining if there is a forward slash in the string: $Repo"
            If ($Repo -match '/') {
                Write-Debug -Message 'String has a forward slash, splitting owner/name'

                $RepoOwner = $Repo.Split('/')[0]
                Write-Debug -Message "Owner name is: $RepoOwner"

                $RepoName = $Repo.Split('/')[1]
                Write-Debug -Message "Repo name is: $RepoName"

                Write-Debug -Message "Adding record to PSObject"
                New-Object -TypeName PSObject -Property @{
                    'Name'  = $RepoName
                    'Owner' = $RepoOwner
                }
            } Else {
                Write-Debug -Message "Could not match a forward slash in the string: $Repo"
                Write-Output "No forward slash matched in: $Repo"
            }
        }
        Write-Debug -Message "Returning hashtable with values: $(Out-String -InputObject $RepoList)"
    }

    End {
        Write-Output -InputObject $RepoList
        Write-Debug -Message 'Exited function: Resolve-GHRepoName'
    }
}