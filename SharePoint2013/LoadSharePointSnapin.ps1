$version = $host | select version

if ($version.Version.Major -gt 1) {

    $host.Runspace.ThreadOptions = "ReuseThread"

}

if ((Get-PSSnapin "Microsoft.SharePoint.PowerShell" -ErrorAction SilentlyContinue) -eq $null) {

    Add-PSSnapin Microsoft.SharePoint.PowerShell    

}