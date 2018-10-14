# GitHub Administration aka GHAdmin

Welcome to the GHAdmin community!

GHAdmin is a Powershell module design to make administration of both your GitHub Enterprise and GitHub.com a little easier. Of course you can use the GUI, but sometimes the CLI is better.

There are a lot of features that we want to add including -

* Creation of Pester tests
* Create a build/test/deploy pipeline
* Package Management
* Documentation

If you're interested in helping out, please feel free to!

## Installation

You can get the latest release of the GHAdmin PowerShell module by cloning this repo. Once that is done, you can import the module using the following command -

```powershell
git clone https://github.com/github/GHAdmin.git
cd ./GHADmin
Import-Module -Name ./GHAdmin
```

## New to GitHub?

If you happen to be new to Git and/or GitHub, we encourage you to check out the following resources to get more familiar with them -

* [Git](https://git-scm.com)
* [Learn Git!](https://try.github.io/levels/1/challenges/1)
* [Book: Pro Git](https://git-scm.com/book/en/v2)
* [GitHub Guide](https://guides.github.com)

## New to GHAdmin

GHAdmin is a PowerShell Core module that helps engineers work and interact with the GitHub platform, primarily through the use of API calls.

Through the use of the API, you can perform tasks such as -

* Creation of Issues & Pull Requests
* Creation of Repos and Organizations
* Create, gather information and remove GitHub Users
* Kick off migration archives
* And more!

## Contributing

Please see our contribution policy located [here](/.github/CONTRIBUTING.md)

## License

Licensed under the MIT License.
