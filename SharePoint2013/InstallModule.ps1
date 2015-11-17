# Update with the location of the downloaded module files # 
$downloadFolder = "C:\SharePoint2013STIGs\"

# Get Program Files directory and set Modules directory path #
$userProfile = $env:USERPROFILE
$modulesPath = Join-Path -Path $userProfile -ChildPath "Documents\WindowsPowerShell\Modules\"
$sp13ModulePath = Join-Path -Path $modulesPath -ChildPath "SharePoint2013STIGs\"

if (!(Test-Path $modulesPath)) {

    Write-Output "$modulesPath does not exist - creating"

    New-Item $modulesPath -type directory

}

if (!(Test-Path $sp13ModulePath)) {

    Write-Output "$sp13ModulePath does not exist - creating"

    New-Item $sp13ModulePath -type directory

    Copy-Item -Path $downloadFolder\* -Destination $sp13ModulePath -Recurse

}