# Update with the location of the downloaded module files # 
$downloadFolder = "C:\IIS7STIGs\"

# Get Program Files directory and set Modules directory path #
$userProfile = $env:USERPROFILE
$modulesPath = Join-Path -Path $userProfile -ChildPath "Documents\WindowsPowerShell\Modules\"
$iis7ModulePath = Join-Path -Path $modulesPath -ChildPath "IIS7STIGs\"

if (!(Test-Path $modulesPath)) {

    Write-Output "$modulesPath does not exist - creating"

    New-Item $modulesPath -type directory

}

if (!(Test-Path $iis7ModulePath)) {

    Write-Output "$iis7ModulePath does not exist - creating"

    New-Item $iis7ModulePath -type directory

    Copy-Item -Path $downloadFolder\* -Destination $iis7ModulePath -Recurse

}