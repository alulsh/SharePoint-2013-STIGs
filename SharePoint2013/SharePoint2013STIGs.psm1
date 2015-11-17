function Set-SecurityValidation {
    
    <#
    .SYNOPSIS
    For every SharePoint web application, configures the security validation timeout to 15 minutes.
    .DESCRIPTION
    Applies findings V-59919 ("SharePoint must support the requirement to initiate a session lock after 15 minutes of system or application inactivity has transpired") and V-59977 ("SharePoint must terminate user sessions upon user logoff, and when idle time limit is exceeded") from the SharePoint 2013 STIG.
    .PARAMETER Timeout
    Optional. Configures the security validation timeout. If not specified, the default value is 15 minutes. The minimum is 1 minute and the maximum is 15 minutes.
    .EXAMPLE
    Set-SecurityValidation
    .EXAMPLE
    Set-SecurityValidation -Timeout 5
    .COMPONENT
    SharePoint 2013
    .LINK
    http://iase.disa.mil/stigs/app-security/app-servers/Pages/sharepoint.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/U_SharePoint_2013_V1R1_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/sharepoint_2013/2015-05-07/finding/V-59919
    .LINK
    https://www.stigviewer.com/stig/sharepoint_2013/2015-05-07/finding/V-59977
    #>

    [CmdletBinding()]
    param(
        [ValidateRange(1,15)]
        [long]$Timeout = 15
    )

    $webApplications = Get-SPWebApplication -IncludeCentralAdministration

    foreach ($webApplication in $webApplications) {
        
        $timeSpan = New-TimeSpan -Minutes $Timeout

        $webApplication.FormDigestSettings.Timeout = $timeSpan

        $webApplication.Update()

        Write-Output "$($webApplication.URL) security validation timeout updated to $timeout minutes"

    }

}

function Set-BrowserFileHandling {
    
    <#
    .SYNOPSIS
    For every SharePoint web application, set browser file handling to strict. 
    .DESCRIPTION
    Applies findings V-59957 ("SharePoint must prevent the execution of prohibited mobile code") from the SharePoint 2013 STIG.
    .EXAMPLE
    Set-BrowserFileHandling
    .COMPONENT
    SharePoint 2013
    .LINK
    http://iase.disa.mil/stigs/app-security/app-servers/Pages/sharepoint.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/U_SharePoint_2013_V1R1_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/sharepoint_2013/2015-05-07/finding/V-59957
    #>

    $webApplications = Get-SPWebApplication -IncludeCentralAdministration

    foreach ($webApplication in $webApplications) {
        
        if($webApplication.BrowserFileHandling -eq "Permissive") {
        
            $webApplication.BrowserFileHandling = "Strict"
            
            $webApplication.Update()

            Write-Output "$($webApplication.URL) browser file handling set to strict"

        }   
        
        else {
            
            Write-Output "$($webApplication.URL) is already STIG compliant - Browser File Handling is strict"

        }   

    }

}

function Disable-OnlineWebPartGallery {

    <#
    .SYNOPSIS
    For every SharePoint web application, disable the Online Web Part Gallery.
    .DESCRIPTION
    Applies findings V-59991 ("SharePoint server access to the Online Web Part Gallery must be configured for limited access") from the SharePoint 2013 STIG.
    .EXAMPLE
    Disable-OnlineWebPartGallery
    .COMPONENT
    SharePoint 2013
    .LINK
    http://iase.disa.mil/stigs/app-security/app-servers/Pages/sharepoint.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/U_SharePoint_2013_V1R1_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/sharepoint_2013/2015-05-07/finding/V-59991
    #>
    
    $webApplications = Get-SPWebApplication -IncludeCentralAdministration

    foreach($webApplication in $webApplications){
    
        if($webApplication.AllowAccessToWebPartCatalog -eq $true) {
            
            $webApplication.AllowAccessToWebPartCatalog = $false

            $webApplication.Update()

            Write-Output "Online web part gallery disabled for $($webApplication.URL)"

        }

        else {

            Write-Output "$($webApplication.URL) is already STIG compliant - Online Web Part Gallery is already disabled"

        }

    }

}

function Set-SiteCollectionAuditLogs {
    
    <#
    .SYNOPSIS
    For every SharePoint site collection, configure the audit logs based on given parameters.
    .DESCRIPTION
    Applies findings V-59941 ("SharePoint must ensure remote sessions for accessing security functions and security-relevant information are audited") from the SharePoint 2013 STIG.
    .PARAMETER AuditEvents
    Mandatory - comma separated list of audit events from the SPAuditMaskType enumeration.
    .PARAMETER TrimLog
    Mandatory - $true or $false value for trimming the audit logs
    .PARAMETER TrimRentention
    Optional - If TrimLog is set to $true, then audit logs will be retained for the provided number of days
    .EXAMPLE
    Set-SiteCollectionAuditLogs -TrimLog $true -TrimRetention 7 -AuditEvents Delete,Undelete,Update,SecurityChange,SchemaChange
    .COMPONENT
    SharePoint 2013
    .LINK
    http://iase.disa.mil/stigs/app-security/app-servers/Pages/sharepoint.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/U_SharePoint_2013_V1R1_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/sharepoint_2013/2015-05-07/finding/V-59941
    .LINK
    https://msdn.microsoft.com/en-us/library/microsoft.sharepoint.spauditmasktype.aspx
    #>

    [CmdletBinding()]
    param(

        [parameter(Mandatory=$true)]
        [string[]]$AuditEvents,

        [parameter(Mandatory=$true)]
        [bool]$TrimLog,

        [int32]$TrimRetention
    )

    $sites = Get-SPSite -limit all
    
    # Events come from the SPAuditMaskType enumeration #
    # https://msdn.microsoft.com/en-us/library/microsoft.sharepoint.spauditmasktype.aspx #

    foreach($event in $AuditEvents) {
        
        # Convert each audit event to an integer, then sum to get the full mask value #    
        $auditmask += ([Microsoft.SharePoint.SPAuditMaskType]::$event).GetHashCode()

    }

    foreach ($site in $sites){
        
        $site.TrimAuditLog = $TrimLog
        
        if ($TrimLog -eq $true) {

            $site.AuditLogTrimmingRetention = $TrimRetention

        }

        $site.Audit.AuditFlags = $auditmask
        $site.Audit.Update()

    }

    Write-Output "Auditing configured for all site collections in the farm"

}

function Set-PrimarySecondarySiteOwner {
    
    <#
    .SYNOPSIS
    For every SharePoint site collection, sets a primary and secondary owner.
    .DESCRIPTION
    Applies finding V-60007 ("A secondary SharePoint Site Collection administrator must be defined when creating a new site collection") from the SharePoint 2013 STIG.
    .PARAMETER PrimaryOwner
    Mandatory - User account of the primary owner
    .PARAMETER SecondaryOwner
    Mandatory - User account of the secondary owner
    .EXAMPLE
    Set-PrimarySecondarySiteOwner -PrimaryOwner "MARS\Mike.Dexter" -SecondaryOwner "MARS\Liz.Lemon"
    .COMPONENT
    SharePoint 2013
    .LINK
    http://iase.disa.mil/stigs/app-security/app-servers/Pages/sharepoint.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/U_SharePoint_2013_V1R1_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/sharepoint_2013/2015-05-07/finding/V-60007
    #>

    [CmdletBinding()]
    param(

        [parameter(Mandatory=$true)]
        [string]$PrimaryOwner,

        [parameter(Mandatory=$true)]
        [string]$SecondaryOwner

    )

    $sites = Get-SPSite -limit all

    foreach ($site in $sites){

        Set-SPSite -Identity $site -OwnerAlias $PrimaryOwner -SecondaryOwnerAlias $SecondaryOwner

    }

    Write-Output "Set the primary owner as $PrimaryOwner and secondary owner as $SecondaryOwner for all site collections"

}