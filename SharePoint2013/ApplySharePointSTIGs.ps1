# Set variables for script #
$Timeout = 15
$TrimLog = $true
$TrimRetention = 7
$AuditEvents = "Delete,Undelete,Update,SecurityChange,SchemaChange"
$PrimaryOwner = "MARS\Mike.Dexter"
$SecondaryOwner = "MARS\Liz.Lemon"

## Load SharePoint2013STIGs Module ##

Import-Module SharePoint2013STIGs

### SharePoint 2013 STIGs ###

Write-Output "`n ----- Applying STIGs for SharePoint 2013 -----"

Write-Output "`n ----- Applying V-59919 from SharePoint 2013 -----"

Set-SecurityValidation -Timeout $Timeout

Write-Output "`n ----- Applying V-59957 from SharePoint 2013 -----"

Set-BrowserFileHandling

Write-Output "`n ----- Applying V-59991 from SharePoint 2013 -----"

Disable-OnlineWebPartGallery

Write-Output "`n ----- Applying V-59941 from SharePoint 2013 -----"

Set-SiteCollectionAuditLogs -TrimLog $TrimLog -TrimRetention $TrimRetention -AuditEvents $AuditEvents

Write-Output "`n ----- Applying V-59941 from SharePoint 2013 -----"

Set-PrimarySecondarySiteOwner -PrimaryOwner $PrimaryOwner -SecondaryOwner $SecondaryOwner