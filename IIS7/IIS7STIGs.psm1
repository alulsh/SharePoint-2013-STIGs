# Get IIS version
$iisVersion = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp\).MajorVersion

# Get operating system version
$windowsVersion = (Get-WmiObject win32_operatingsystem).version

### Begin IIS 7 Server STIGs ###

function Disable-SMTP {

    <#
    .SYNOPSIS
    Disables SMTP on the server
    .DESCRIPTION
    Applies finding V-2261 ("A web server must limit e-mail to outbound only") from the IIS 7 Server STIG, which disables SMTP if it is running on the server
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
    
    Import-Module ServerManager

    $SMTP = Get-WindowsFeature SMTP-Server

    if ($SMTP.Installed -eq $true){
    
        Write-Output "Server is not STIG compliant - uninstalling SMTP service"
        Remove-WindowsFeature SMTP-server
        Write-Output "SMTP service uninstalled"

    }

    else {
    
        Write-Output "Server is STIG compliant - SMTP Service is not installed"
    
    }

}

function Remove-SampleCode {

    <#
    .SYNOPSIS
    Removes IIS and ASP.NET related sample code from the server
    .DESCRIPTION
    Applies finding V-13621 ("All web server documentation, sample code, example applications, and tutorials must be removed from a production web server.") from the IIS 7 Server STIG.
    .EXAMPLE
    Remove-SampleCode
    .COMPONENT
    IIS 7.0 Web Server
    .LINK
    http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_IIS_7-0_V1R8_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/iis_7.0_web_server/2015-06-01/finding/V-13621
    #>

    $iisRootFolder = "C:\inetpub"
    $adminScriptsFolder = Join-Path -Path $iisRootFolder -Childpath "AdminScripts"
    $0409Folder = Join-Path -Path $adminScriptsFolder -Childpath "0409"
    $sampleFolder = Join-Path -Path $iisRootFolder -Childpath "scripts\IISSamples"
    $msadcFolder = "C:\Program Files\Common Files\system\msadc"
    
    Set-Location $iisRootFolder

    # Delete AdminScripts folder and subfolders #

    if (Test-Path $adminScriptsFolder) {
        
        Write-Output "Not STIG compliant - AdminScripts subfolder found in $iisRootFolder - deleting files and sub-folders"
        
        takeown /f AdminScripts /r /d y
        
        if (Test-Path $0409Folder) {
            
            takeown /f $0409Folder /r /d y
            CMD /C "icacls $0409Folder /grant BUILTIN\ADMINISTRATORS:(OI)(CI)F"
            
            Push-Location $0409Folder
            Get-ChildItem * -Recurse | Remove-Item
            Pop-Location

            Write-Output "$0409Folder deleted"
        
        }
        
        Push-Location $adminScriptsFolder
        Get-ChildItem * -Recurse | Remove-Item
        Pop-Location

        Remove-Item $adminScriptsFolder -Recurse
        
        Write-Output "$0409Folder deleted"
        
    }

    else {

        Write-Output "STIG Compliant - $adminScriptsFolder does not exist"
    
    }

    # Delete Sample folder #

    if (Test-Path $sampleFolder) {
        
        Write-Output "$sampleFolder folder exists - please delete"
    
    }
    else {
    
        Write-Output "$sampleFolder does not exist"
    
    }

    # Delete MSADC folder #

    if (Test-Path $msadcFolder) {
        
        Write-Output "Not STIG compliant - $msadcFolder folder exists - deleting"
        
        Set-Location "C:\Program Files\Common Files\System\"
        
        takeown /f msadc /r /d y
        icacls msadc /grant Administrators:f /t /q
        Remove-Item $msadcFolder -recurse
        
        Write-Output "Deleted $msadcFolder"
        
    }
    
    else {
    
        Write-Output "STIG compliant - $msadcFolder does not exist"
    
    }

}

### Begin IIS 7 Web Site STIGs ###

function Set-MaxConnections {

    <#
    .SYNOPSIS
    Applies finding V-2240 ("Web sites must limit the number of simultaneous requests") from the IIS 7 Web Site STIG.
    .DESCRIPTION
    For every IIS Site, configures the maximum number of allowed connections
    .PARAMETER Limit
    Optional. Configures the maximum number of connections allowed for all IIS sites. If not specified, the default value is the maximum value of 4,294,967,294.
    .EXAMPLE
    Set-MaxConnections
    .EXAMPLE
    Set-MaxConnections -Limit 4000
    .COMPONENT
    IIS 7.0 Web Site
    .LINK
    http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_IIS_7-0_V1R8_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-2240
    #>

    [CmdletBinding()]
    param(
        [ValidateRange(0,4294967294)]
        [long]$Limit = 4294967294
    )

    $serverConfiguration = "/system.applicationHost/sites/*"

    $applicationHosts = Get-WebConfiguration -filter $serverConfiguration

    foreach ($application in $applicationHosts) {
        
        $name = $application.Name
        
        Set-WebConfigurationProperty -Filter $serverConfiguration -name Limits -Value @{MaxConnections=$limit}

    }

}

function Enable-NetworkLevelAuthentication {

    <#
    .SYNOPSIS
    Applies finding V-2249 ("Web Server/site administration must be performed over a secure path") from the IIS 7 Web Site STIG.
    .DESCRIPTION
    Configures the server to only accept remove connections from computers running remote desktop with Network Level Authentication enabled.
    .EXAMPLE
    Enable-NetworkLevelAuthentication
    .COMPONENT
    IIS 7.0 Web Site
    .LINK
    http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_IIS_7-0_V1R8_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-2249
    #>

    $terminalServerSettings =  Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices
    
    if ($terminalServerSettings.UserAuthenticationRequired -eq 0){
    
        Write-Output "Not STIG compliant - Network Level Authentication not enabled"
        $terminalServerSettings.SetUserAuthenticationRequired(1)
        Write-Output "Network level authentication enabled"

    }
    
    else {
        
        Write-Output "STIG Compliant - Network Level Authentication already enabled for Remote Desktop"
    
    }

}

function Set-DoubleEscapingURLs {

    <#
    .SYNOPSIS
    Applies finding V-26045 ("The web-site must not allow double encoded URL requests.") from the IIS 7 Web Site STIG.
    .DESCRIPTION
    Disables double escaping in URLs in IIS request filtering settings.
    .EXAMPLE
    Set-DoubleEscapingURLs
    .COMPONENT
    IIS 7.0 Web Site
    .LINK
    http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_IIS_7-0_V1R8_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-26045
    #>  

    $serverConfig = "/system.webServer/security/requestFiltering"
    $requestFiltering = Get-WebConfiguration -filter $serverConfig

    # Apply configuration at the server level first #

    if ($requestFiltering.allowDoubleEscaping -eq $true){
        
        Write-Output "Server configuration is not STIG compliant - setting double escaping to false"
        
        $requestFiltering.allowDoubleEscaping = $false
        $requestFiltering | Set-WebConfiguration -filter $serverConfig -PSPath IIS:\

    }
    
    else {
        
        Write-Output "Server configuration is STIG compliant - allow double escaping already set to false"
    
    }

    # Apply configuration to each IIS site via a loop #

    $websites = Get-WebSite

    foreach ($website in $websites) {

        $siteName = $website.Name

        if ($iisVersion -le 7) {

                C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.webServer/security/requestFiltering /allowdoubleescaping:false

        } 
            
        else {

            $requestFiltering = Get-WebConfiguration -filter $serverConfig -Location $siteName
        
            if ($requestFiltering.allowDoubleEscaping -eq $true){
        
                Write-Output "$siteName is not STIG compliant - setting allow double escaping to false"
           
                Set-WebConfigurationProperty -Filter $serverConfig -name allowDoubleEscaping -Value False -PSPath IIS:\sites\$siteName
        
            } else {
        
                Write-Output "$siteName is STIG Compliant - allow double escaping is already set to false"
        
            }
        }
       
    }

}

function Set-HighBitCharacters {

    <#
    .SYNOPSIS
    Applies finding V-26044 ("The web-site must not allow non-ASCII characters in URLs.") from the IIS 7 Web Site STIG.
    .DESCRIPTION
    Disables high bit non-ASCII characters in IIS request filtering
    .EXAMPLE
    Set-HighBitCharacters
    .COMPONENT
    IIS 7.0 Web Site
    .LINK
    http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_IIS_7-0_V1R8_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-26044
    #>

    $serverConfig = "/system.webServer/security/requestFiltering"
    $requestFiltering = Get-WebConfiguration -filter $serverConfig

    # Apply configuration at the server level first #

    if ($requestFiltering.allowHighBitCharacters -eq $true){
        
        Write-Output "Server configuration is not STIG compliant - setting allow high bit characters to false"
        
        $requestFiltering.allowHighBitCharacters = $false
        $requestFiltering | Set-WebConfiguration -filter $serverConfig -PSPath IIS:\

    }

    else {
        
        Write-Output "Server configuration is STIG compliant - allow high bit characters already set to false"
    
    }

    # Apply configuration to each IIS site via a loop #

    $websites = Get-WebSite

    foreach ($website in $websites) {
            
        $siteName = $website.Name

        if ($iisVersion -le 7) {

                C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.webServer/security/requestFiltering /allowHighBitCharacters:false

        } 

        else {
        
            $requestFiltering = Get-WebConfiguration -filter $serverConfig -Location $siteName
        
            if ($requestFiltering.allowHighBitCharacters -eq $true) {
        
                Write-Output "$siteName is not STIG compliant - setting allow high bit characters to false"
                Set-WebConfigurationProperty -Filter $serverConfig -name allowHighBitCharacters -Value False -PSPath IIS:\sites\$siteName
        
            }
        
            else {
           
                Write-Output "$siteName - STIG Compliant - Allow high bit characters is set to false"
        
            }

        }
       
    }

}

function Set-AlternateHostName {

    <#
    .SYNOPSIS
    Applies finding V-13702 ("The Content Location header must not contain proprietary IP addresses") from the IIS 7 Web Site STIG.
    .DESCRIPTION
    Changes the IIS request headers to send a hostname in lieu of the default setting of an IP address.
    .EXAMPLE
    Set-AlternateHostName
    .COMPONENT
    IIS 7.0 Web Site
    .LINK
    http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_IIS_7-0_V1R8_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-13702
    #>

    $fqdn = "$env:computername.$env:userdnsdomain"

    $runtimeConfig = Get-WebConfiguration -filter "/system.webServer/serverRuntime"

    if (!$runtimeConfig.alternateHostName){

        Write-Output "Server is not STIG compliant - alternateHostName is blank"
           
        Set-WebConfigurationProperty -Filter "/system.webServer/serverRuntime" -name alternateHostName -Value $fqdn

    }

    else {

        Write-Output "Server is STIG Compliant - alternateHostName is $runtimeConfig.alternateHostName"
    
    }
        
    <#
        $websites = Get-WebSite

        foreach($website in $websites){

            $siteName = $website.Name

            if ($iisVersion -le 7) {

                 C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.webServer/serverRuntime /alternateHostName:$fqdn

            } 

            else {
        
                $runtimeConfig = Get-WebConfiguration -filter "/system.webServer/serverRuntime" -Location $siteName
        
                if (!$runtimeConfig.alternateHostName){
        
                   Write-Output "$siteName - Not STIG compliant - alternateHostName is blank"
           
                   Set-WebConfigurationProperty -Filter "/system.webServer/serverRuntime" -name alternateHostName -Value $fqdn
           
                }

                else {
           
                   Write-Output "$siteName - STIG Compliant - alternateHostName is $runtimeConfig.alternateHostName"
        
                }
            }
       
        }
    #>

}

function Set-LogDataFields {
    
    <#
    .SYNOPSIS
    Applies finding V-13688 ("Log files must consist of the required data fields") from the IIS 7 Web Site STIG.
    .DESCRIPTION
    Configures IIS log settings in accordance with STIG requirements.
    .EXAMPLE
    Set-LogDataFields
    .COMPONENT
    IIS 7.0 Web Site
    .LINK
    http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_IIS_7-0_V1R8_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-13688
    #>
    
    Set-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name logfile.logExtFileFlags -value "Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,TimeTaken,ServerPort,UserAgent,Referer,HttpSubStatus"
    
    Write-Output "`nConfigured IIS logs per STIG guidelines"

}

function Set-HandlerMappings {
    <#
    .SYNOPSIS
    Applies finding V-2267 ("Unapproved script mappings in IIS 7 must be removed") from the IIS 7 Web Site STIG.
    .DESCRIPTION
    Applies finding V-2267 ("Unapproved script mappings in IIS 7 must be removed") from the IIS 7 Web Site STIG.
    .EXAMPLE
    Set-HandlerMappings -BlackListFile "C:\BlackList.csv"
    .COMPONENT
    IIS 7.0 Web Site
    .LINK
    http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_IIS_7-0_V1R8_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-2267
    #>

    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$BlackListFile
    )

    Write-Output "`nImporting CSV from $BlackListFile"

    $handlerMappings = Import-CSV -Path $BlackListFile

    foreach ($handlerMapping in $handlerMappings) {
        
        Remove-WebHandler -Name $handlerMapping.Name
        
        Write-Output "`nRemoving $handlerMapping.Name from IIS"
        
    }

}

## Supporting functions for applying V-26046 from the IIS 7 Site STIG ##

function Add-FileExtensionServer ($extension,$allowed) {
    
    C:\Windows\System32\inetsrv\appcmd.exe set config -section:system.webServer/security/requestFiltering /+"fileExtensions.[fileExtension='$extension',allowed='$allowed']"
    
}

function Add-FileExtensionSite ($extension,$allowed,$website) {

    C:\Windows\System32\inetsrv\appcmd.exe set config $website -section:system.webServer/security/requestFiltering /+"fileExtensions.[fileExtension='$extension',allowed='$allowed']"

}

function Add-AllowedFileExtensionsServer ($file) {
    
    $allowedExtensions = Import-CSV -Path $file
    
    foreach ($extension in $allowedExtensions) {
        
        Write-Output "Setting $($extension.fileExtension) to allowed in Request Filtering"
        
        Add-FileExtensionServer $extension.fileExtension $extension.Allowed
    
    }

}

function Add-AllowedFileExtensionsSite ($file,$website) {
    
    $allowedExtensions = Import-CSV -Path $file
    
    foreach ($extension in $allowedExtensions) {
        
        Write-Output "Setting $($extension.fileExtension) to allowed in Request Filtering for $website"

        Add-FileExtensionSite $extension.fileExtension $extension.Allowed $website
    
    }

}

## Main function for applying V-26046 from the IIS 7 Site STIG ##

function Disable-UnlistedFileExtensions {

    <#
    .SYNOPSIS
    Applies finding V-26046 ("The production web-site must filter unlisted file extensions in URL requests") from the IIS 7 Web Site STIG.
    .DESCRIPTION
    Disables unlisted file extensions in IIS request filtering, then adds allowed file extensions based on a CSV file
    .EXAMPLE
    Disable-UnlistedFileExtensions -AllowedFileExtensionsList "C:\AllowedFileExtensions.csv"
    .COMPONENT
    IIS 7.0 Web Site
    .LINK
    http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_IIS_7-0_V1R8_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-26046
    #>

    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$AllowedFileExtensionsList
    )

    $serverConfiguration = "/system.webServer/security/requestFiltering/fileExtensions"
    
    $requestFiltering = Get-WebConfiguration -filter $serverConfiguration
    
    if ($requestFiltering.allowUnlisted -eq "True"){
    
        Write-Output "Not STIG Compliant - Unlisted file extensions are allowed"
        
        $requestFiltering.allowUnlisted = $false
        $requestFiltering | Set-WebConfiguration -filter $serverConfiguration -PSPath IIS:\
    
    }

    else {
    
        Write-Output "Server setting is STIG compliant - unlisted file extensions are not allowed"
    
    }

    # Add-AllowedFileExtensionsServer $AllowedFileExtensionsList

    $websites = Get-WebSite | Where-Object {$_.name -ne "SharePoint Web Services" -and $_.name -ne "Default Web Site"}
    
    foreach ($website in $websites) {

        Add-AllowedFileExtensionsSite $AllowedFileExtensionsList $website.Name

    }

}