function Set-GlobalAuthorizationRule {

    <#
    .SYNOPSIS
    Sets authorization at the server level to Administrators only, and resets SharePoint IIS sites back to All Users.
    .DESCRIPTION
    Applies finding V-26006 ("A global authorization rule to restrict access must exist on the web server.") from the IIS 7 Server STIG. Sets authorization at the server level to Administrators only, and resets SharePoint IIS sites back to All Users.
    .EXAMPLE
    Set-GlobalAuthorizationRule
    .COMPONENT
    IIS 7.0 Web Server
    .LINK
    http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_IIS_7-0_V1R8_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/iis_7.0_web_server/2015-06-01/finding/V-26006
    #>

    $serverConfiguration = "/system.webServer/security/authorization/add"
    $siteConfiguration = "/system.webServer/security/authorization/*"

    Write-Output "Restricting server level access to Administrators only"

    $authRules = Get-WebConfiguration -filter $serverConfiguration
    $authRules.Users = "Administrators"
    $authRules | Set-WebConfiguration -filter $serverConfiguration -PSPath IIS:\

    # Allow All Users to access existing IIS sites #

    $websites = Get-WebSite

    foreach ($website in $websites) {

        $siteName = $website.Name

        Write-Output "$siteName authorization reset to All Users"
        
        Set-Location "C:\Windows\system32\inetsrv"  

        .\appcmd.exe set config $siteName -section:system.webServer/security/authorization /+"[accessType='Allow',Users='All Users']"
        .\appcmd.exe set config $siteName -section:system.webServer/security/authorization /-"[accessType='Allow',Users='Administrators']"

        #Set-WebConfiguration -Filter $siteConfiguration -Value (@{AccessType="Allow"; Users="*"}) -PSPath IIS: -Location $siteName  
       
    }

}

function Disable-FileSystemObject {

    <#
    Applies finding V-13700 from the IIS 7 STIG
    #>

    New-PSDrive -Name HKCR -PsProvider Registry -Root HKEY_CLASSES_ROOT

    try {
        
        $fsoKey = Get-Item "HKCR:\CLSID\{0D43FE01-F093-11CF-8940-00A0C9054228}"
    
    }
    
    catch {
    
        Write-Output 'HKCR:\CLSID\{0D43FE01-F093-11CF-8940-00A0C9054228}' does not exist
    
    }

    if ($fsoKey) {

        $fsoParentKey = "TypeLib\{420B2830-E718-11CF-893D-00A0C9054228}\1.0\0\win32\"
        #$fsoParentKey2 = "TypeLib\{420B2830-E718-11CF-893D-00A0C9054228}\1.0\0\win64\"
        
        Write-Output "Not STIG compliant - FileSystemObject is enabled - disabling"
        
        $key = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey($fsoParentKey,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
        $acl = $key.GetAccessControl();
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule ("BUILTIN\Administrators","FullControl","Allow")

        $acl.SetAccessRule($rule)
        $key.SetAccessControl($acl)
        
        CMD /c "regsvr32 "C:\windows\system32\scrrun.dll" /u"

    }

    else {
        
        Write-Output "STIG compliant - FileSystemObject is not enabled"
    
    }

}

function Disable-AnonymousAccess {
    
    <#
    .SYNOPSIS
    THIS FUNCTION MAY BE DEPRECATED FOR SP13 IN CLAIMS MODE
    .DESCRIPTION
    Applies finding V-6537
    .EXAMPLE
    Disable-SMTP
    .COMPONENT
    IIS 7.0 Web Server
    .LINK
    http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_IIS_7-0_V1R8_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/iis_7.0_web_server/2015-06-01/finding/V-2261
    #>
   
    $serverConfiguration = "/system.webServer/security/authentication/AnonymousAuthentication"
    $anonymousAuthentication = Get-WebConfiguration -Filter $serverConfiguration
    
    if ($anonymousAuthentication.Enabled -eq "True") {
        
        Write-Output "Disabling anonymous authentication at the IIS server level"
        
        Set-WebConfigurationProperty -Filter $serverConfiguration -Name enabled -Value (@{enabled="False"})
    
    }
    
    $websites = Get-WebSite
    
    foreach ($website in $websites) {

        $siteName = $website.Name

        Write-Output "Setting anonymous authentication enabled to false for $siteName"

        Set-WebConfiguration -Filter $serverConfiguration -Value (@{enabled="False"}) -PSPath IIS:\ -Location $siteName  

    }

}

function Set-GlobalTrustLevel {

    <#
    .SYNOPSIS
    THIS FUNCTION MAY BE DEPRECATED FOR SP2013
    .DESCRIPTION
    Applies finding V-26034 ("The production web-site must configure the Global .NET Trust Level") from the IIS 7 Web Site STIG.
    .EXAMPLE
    Set-GlobalTrustLevel
    .COMPONENT
    IIS 7.0 Web Site
    .LINK
    http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_IIS_7-0_V1R8_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-26034
    #>

    $configuration = "/system.web/trust"
    $sharepointWebServices = Get-WebSite -Name "SharePoint Web Services"
    
    C:\Windows\System32\inetsrv\appcmd.exe set config /commit:WEBROOT /section:trust /level:Medium

    Set-WebConfigurationProperty -filter $configuration -name level -value Medium
    
    if ($sharepointWebServices) {
        
        Set-WebConfigurationProperty -filter $configuration -name level -value Full -PSPath "IIS:\Sites\SharePoint Web Services"
    
    }
    
}