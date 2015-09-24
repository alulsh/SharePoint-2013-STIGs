# Update with the location of the downloaded module files # 
$downloadFolder = "C:\SQL2012STIGs\"

# Get Program Files directory and set Modules directory path #
$userProfile = $env:USERPROFILE
$modulesPath = Join-Path -Path $userProfile -ChildPath "Documents\WindowsPowerShell\Modules\"
$sql12ModulePath = Join-Path -Path $modulesPath -ChildPath "SQL2012STIGs\"

if (!(Test-Path $modulesPath)) {

    Write-Output "$modulesPath does not exist - creating"

    New-Item $modulesPath -type directory

}

if (!(Test-Path $sql12ModulePath)) {

    Write-Output "$sql12ModulePath does not exist - creating"

    New-Item $sql12ModulePath -type directory

    Copy-Item -Path $downloadFolder\* -Destination $sql12ModulePath -Recurse

}