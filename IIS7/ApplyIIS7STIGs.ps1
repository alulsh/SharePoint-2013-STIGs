## Load IIS7STIGs Module ##

Import-Module IIS7STIGs

# Get CSV files for IIS 7 Web Site STIGs
# Change to your own files if you do not want to use the default files

$moduleBase = (Get-Module IIS7STIGs).ModuleBase
$blacklist = Join-Path -Path $moduleBase -ChildPath "Blacklist.csv"
$fileExtensionsList = Join-Path -Path $moduleBase -ChildPath "AllowedFileExtensions.csv

### IIS 7 Server STIGs ###

Write-Output "`n ----- Applying STIGs for IIS 7 Server -----"

Write-Output "`n ----- Applying V-13621 from IIS 7 Server -----"

Remove-SampleCode

Write-Output "`n ----- Applying V-2261 from IIS 7 Server -----"

Disable-SMTP

Write-Output "`n ----- Applying V-26006 from IIS 7 Server -----"

Set-GlobalAuthorizationRule

### IIS 7 Site STIGs ###

Write-Output "`n ----- Applying STIGs for IIS 7 Site -----"

Write-Output "`n ----- Applying V-2267 from IIS 7 Site -----"

Set-HandlerMappings -Blacklist $blacklist

Write-Output "`n----- Applying V-13688 from IIS 7 Site -----"

Set-LogDataFields

Write-Output "`n----- Applying V-13702 from IIS 7 Site -----"

Set-AlternateHostName

Write-Output "`n----- Applying V-2240 from IIS 7 Site -----"

Set-MaxConnections

Write-Output "`n----- Applying V-2249 from IIS 7 Site -----"

Enable-NetworkLevelAuthentication

Write-Output "`n----- Applying V-26044 from IIS 7 Site -----"

Set-HighBitCharacters

Write-Output "`n----- Applying V-26045 from IIS 7 Site -----"

Set-DoubleEscapingURLs

Write-Output "`n----- Applying V-26046 from IIS 7 Site -----"

Disable-UnlistedFileExtensions -AllowedFileExtensionsList $fileExtensionsList