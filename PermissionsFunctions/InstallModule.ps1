# Update with the location of the downloaded module files # 
$downloadFolder = "C:\PermissionsFunctions\"

# Get Program Files directory and set Modules directory path #
$userProfile = $env:USERPROFILE
$modulesPath = Join-Path -Path $userProfile -ChildPath "Documents\WindowsPowerShell\Modules\"
$permissionsModulePath = Join-Path -Path $modulesPath -ChildPath "PermissionsFunctions\"

if (!(Test-Path $modulesPath)) {

    Write-Output "$modulesPath does not exist - creating"

    New-Item $modulesPath -type directory

}

if (!(Test-Path $permissionsModulePath)) {

    Write-Output "$permissionsModulePath does not exist - creating"

    New-Item $permissionsModulePath -type directory

    Copy-Item -Path $downloadFolder\* -Destination $permissionsModulePath -Recurse

}