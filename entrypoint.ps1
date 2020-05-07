$dir = Get-ChildItem -Path ./
New-Item -Path ./GHAdminTest.psm1
Foreach-object -InputObject $dir -Process {Get-Content -Path $_.FullName | Add-Content -Path ./GHAdminTest.psm1}
Get-Content -Path ./GHAdminTest.psm1