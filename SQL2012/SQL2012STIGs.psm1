# Helper function to get SQL Server service accounts based on the instance name

function Get-SqlServerAccounts {
    
    [CmdletBinding()]
    Param 
    (
        [parameter(Mandatory=$true)]
        [string]$InstanceName
    )

    $SqlAccounts = @{}

    if ($InstanceName -eq "MSSQLSERVER") {
    
        $SqlAccounts.SqlServerAccount = "NT SERVICE\MSSQLSERVER"
        $SqlAccounts.SqlAgentAccount = "NT SERVICE\SQLSERVERAGENT"
        $SqlAccounts.FullTextAccount = "NT SERVICE\MSSQLFDLauncher"
        
    }

    else {
            
        $SqlAccounts.SqlServerAccount = "NT SERVICE\MSSQL`$$InstanceName"
        $SqlAccounts.SqlAgentAccount = "NT SERVICE\SQLAGENT`$$InstanceName"         
        $SqlAccounts.FullTextAccount = "NT SERVICE\MSSQLFDLauncher`$$InstanceName"  
        
    }

    return $SqlAccounts

}

# SQL 2012 Database STIGs

function Set-MaxConnections {

    <#
    .SYNOPSIS
    Set the maximum number of allowed simultaneous connections to SQL Server.
    .DESCRIPTION
    Applies finding V-41422 ("SQL Server must protect against or limit the effects of the organization-defined types of Denial of Service (DoS) attacks") from the SQL 2012 Database STIG.
    .EXAMPLE
    Set-MaxConnections -ServerName jupitersql1\PLUTO -MaxConnections 5000
    .EXAMPLE
    Set-MaxConnections -ServerName jupitersql1 -MaxConnections 5000
    .EXAMPLE
    Set-MaxConnections -ServerName jupitersql1\PLUTO
    .PARAMETER ServerName
    Name of the SQL server in the format hostname\instance (named instance) or hostname (default instance)
    .PARAMETER Limit
    Maximum number of SQL Server connections to configure. The minimum is 0 and the maximum is 32,767. If this parameter is missing then the default value is the maxmimum of 32,767.
    .COMPONENT
    SQL Server 2012 Database
    .LINK
    http://iase.disa.mil/stigs/app-security/database/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_SQL_Server_2012_V1R7_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database/2015-06-23/finding/V-41422
    #>

    [CmdletBinding()]
    Param 
    (
        [parameter(Mandatory=$true)]
        [string]$ServerName,
        
        [parameter()]
        [ValidateRange(0,32767)]
        [int32]$Limit = 32767
    )

    $sqlConnection = New-Object System.Data.SqlClient.SqlConnection "server=$serverName;database=master;Integrated Security=SSPI"
    $sqlConnection.Open()

    $sqlCommand = $sqlConnection.CreateCommand()

    $query = @"
        USE MASTER

        EXEC sys.sp_configure N'show advanced options', N'1' RECONFIGURE WITH OVERRIDE
        EXEC sys.sp_configure N'user connections', $Limit
        EXEC sys.sp_configure N'show advanced options', N'0' RECONFIGURE WITH OVERRIDE
"@

    $sqlCommand.CommandText = $query
    
    $sqlCommand.ExecuteNonQuery()

    $sqlConnection.Close()

}

# SQL 2012 Database Instance STIGs

function Set-SQLDataRootDirectoryPermissions {

    <#
    .SYNOPSIS
    Removes local users group from the SQL Server Data Root directory.
    .DESCRIPTION
    Applies finding V-54859 ("The OS must limit privileges to the SQL Server Data Root directory and its subordinate directories and files.") from the SQL 2012 Database Instance STIG.
    .EXAMPLE
    Set-SQLDataRootDirectoryPermissions -InstanceName PLUTO
    .EXAMPLE
    Set-SQLDataRootDirectoryPermissions -InstanceName MSSQLSERVER
    .PARAM InstanceName
    Name of the SQL Server instance without the hostname
    .COMPONENT
    SQL Server 2012 Database Instance
    .LINK
    http://iase.disa.mil/stigs/app-security/database/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_SQL_Server_2012_V1R7_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-54859
    #>
    
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$InstanceName
    )

    $sqlDataRoot = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$instanceName\Setup\").SqlDataRoot
    # Permissions on default data path are already STIG-compliant #
    $defaultDataPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$instanceName\MSSQLSERVER\").DefaultData

    # Remove local users groups from SqlDataRoot #

    if (Test-Path $sqlDataRoot) {

        Revoke-Permissions -SecurityPrincipal "BUILTIN\USERS" -Path $sqlDataRoot

        Write-Output "Removed local users group from $sqlDataRoot"

    }

    else {

        Write-Output "$sqlDataRoot does not exist"

    }

}

function Disable-SaAccount {

    <#
    .SYNOPSIS
    Disables the default SA account in SQL Server
    .DESCRIPTION
    Applies finding V-40936 ("SQL Server default account sa must be disabled") from the SQL 2012 Database Instance STIG.
    .EXAMPLE
    Disable-SaAccount -ServerName jupitersql1\PLUTO
    .EXAMPLE
    Disable-SaAccount -ServerName jupitersql1\MSSQLSERVER
    .COMPONENT
    SQL Server 2012 Database Instance
    .LINK
    http://iase.disa.mil/stigs/app-security/database/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_SQL_Server_2012_V1R7_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-40936
    #>

    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$ServerName
    )

    $SQLServer  = New-Object "Microsoft.SQLServer.Management.Smo.Server" $serverName

    # SA Account has a SID and ID of 1 even when it is renamed #

    $saAccount = $SQLServer.Logins | Where-Object {$_.Id -eq 1}

    if (!$saAccount.isDisabled) {

        Write-Output "Not STIG compliant - Default SA account is enabled"

        $saAccount.Disable()

    }

    else {

        Write-Output "STIG Compliant - SA account is already disabled"

    }

}

function Set-SQLSoftwareLibrariesPermissions {

    <#
    .SYNOPSIS
    Applies finding V-40944 ("The OS must limit privileges to change SQL Server software resident within software libraries (including privileged programs).") from the SQL 2012 Database Instance STIG.
    .DESCRIPTION
    Limits permissions on the SQL Server binn, install, and shared code directories.
    .PARAM InstanceName
    Name of the SQL Server instance without the hostname
    .EXAMPLE
    Set-SQLSoftwareLibrariesPermissions -InstanceName MSSQLSERVER
    .EXAMPLE
    Set-SQLSoftwareLibrariesPermissions -InstanceName PLUTO
    .COMPONENT
    SQL Server 2012 Database Instance
    .LINK
    http://iase.disa.mil/stigs/app-security/database/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_SQL_Server_2012_V1R7_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-40944
    #>  

    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$InstanceName
    )

    $accounts = Get-SqlServerAccounts -InstanceName $InstanceName
    
    $sqlInstallation = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$instanceName\Setup\").SqlProgramDir
    $instanceInstallation = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$instanceName\Setup\").SqlPath

    $binnFolder = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$instanceName\Setup\").SQLBinRoot
    $sharedCodeFolder = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\110\").SharedCode
    $installFolder = "$instanceInstallation\Install"

    if (Test-Path $binnFolder) {

        Write-Output "$binnFolder exists in $instanceInstallation"
    
        Disable-Inheritance -Path $binnFolder
        Revoke-Permissions -SecurityPrincipal "BUILTIN\USERS" -Path $binnFolder
        Grant-Permissions -SecurityPrincipal $accounts.SqlServerAccount -Path $binnFolder -Permissions "Read,ReadAndExecute"
        Grant-Permissions -SecurityPrincipal $accounts.SqlAgentAccount -Path $binnFolder -Permissions "FullControl"

    }

    else {

        Write-Output "$binnFolder does not exist in $instanceInstallation"

    }

    if (Test-Path $sharedCodeFolder) {

        Write-Output "$sharedCodeFolder exists"
    
        Set-Location $sharedCodeFolder
        Set-Location ..

        takeown /f Shared /a
    
        Disable-Inheritance -Path $sharedCodeFolder

        # Function does not remove permissions, unsure why, needs troubleshooting #
        Revoke-Permissions -SecurityPrincipal "BUILTIN\USERS" -Path $sharedCodeFolder
        
        # Network Service needs Read, ReadAndExecute rights for SQL Server Configuration Manager to work
        Grant-Permissions -SecurityPrincipal "NT AUTHORITY\NETWORK SERVICE" -Path $sharedCodeFolder -Permissions "Read,ReadAndExecute"
        Grant-Permissions -SecurityPrincipal $accounts.SqlServerAccount -Path $sharedCodeFolder -Permissions "Read,ReadAndExecute"
        Grant-Permissions -SecurityPrincipal $accounts.SqlAgentAccount -Path $sharedCodeFolder -Permissions "Read,ReadAndExecute,Write"
        Grant-Permissions -SecurityPrincipal $accounts.FullTextAccount -Path $sharedCodeFolder -Permissions "Read,Write"

    }

    else {

       Write-Output "$sharedCodeFolder does not exist"

    }

    if (Test-Path $installFolder) {

        Write-Output "$installFolder exists in $instanceInstallation"

        Disable-Inheritance -Path $installFolder
        Revoke-Permissions -SecurityPrincipal "BUILTIN\USERS" -Path $installFolder
        Grant-Permissions -SecurityPrincipal $accounts.SqlServerAccount -Path $binnFolder -Permissions "Read,ReadAndExecute" 
    }

    else {

        Write-Output "$installFolder does not exist in $instanceInstallation"

    }

}

function Enable-FileAuditing {

    <#
    .SYNOPSIS
    Enables NTFS auditing on SQL server software library files.
    .DESCRIPTION
    Applies finding V-40950 ("SQL Server must support the employment of automated mechanisms supporting the auditing of the enforcement actions") from the SQL 2012 Database Instance STIG.
    .PARAM InstanceName
    Name of the SQL Server instance without the hostname
    .EXAMPLE
    Enable-FileAuditing -Instance MSSQLSERVER
    .EXAMPLE
    Enable-FileAuditing -Instance Pluto
    .COMPONENT
    SQL Server 2012 Database Instance
    .LINK
    http://iase.disa.mil/stigs/app-security/database/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_SQL_Server_2012_V1R7_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-40950
    #>
    
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$InstanceName
    )

    $sqlInstallation = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$instanceName\Setup\").SqlProgramDir

    $sqlACL = New-Object System.Security.AccessControl.DirectorySecurity

    $auditEvents = "ExecuteFile,ReadData,ReadAttributes,ReadExtendedAttributes,CreateFiles,AppendData,WriteAttributes,WriteExtendedAttributes,Delete,ReadPermissions"

    $AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone",$auditEvents,"ContainerInherit,ObjectInherit","None","Success,Failure")

    $sqlACL.AddAuditRule($AccessRule)

    Set-Acl -Path $sqlInstallation -AclObject $sqlACL
    
    Write-Output "NTFS auditing enabled on SQL server data libraries"

}

function Rename-SaAccount {

    <#
    .SYNOPSIS
    Renames the sa account.
    .DESCRIPTION
    Applies finding V-41037 ("SQL Server default account sa must have its name changed") from the SQL 2012 Database Instance STIG.
    .EXAMPLE
    Rename-SaAccount
    .COMPONENT
    SQL Server 2012 Database Instance
    .LINK
    http://iase.disa.mil/stigs/app-security/database/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_SQL_Server_2012_V1R7_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41037
    #>

    [CmdletBinding()]
    Param 
    (
        [parameter(Mandatory=$true)]
        [string]$ServerName,
        
        [parameter(Mandatory=$true)]
        [string]$NewName
    )

    $SQLServer  = New-Object "Microsoft.SQLServer.Management.Smo.Server" $serverName

    # SA Account has a SID and ID of 1 even when it is renamed #

    $saAccount = $SQLServer.Logins | Where-Object {$_.Id -eq 1 -and $_.Name -eq "sa"}

    if ($saAccount) {

        Write-Output "Not STIG compliant - Default SA account has not been renamed"

        $saAccount.Rename($newName)

    }

    else {
        
        Write-Output "STIG Compliant - SA account was renamed"

    }

}

function Set-SQLServerAuditing {

    <#
    .SYNOPSIS
    Configures SQL Server auditing in accordance with DoD guidelines.
    .DESCRIPTION
    Applies findings V-41402 from the SQL 2012 Database STIG and V-41021, V-41022, V-41027, V-41028, V-41029, V-41030, V-41031, V-41032, V-41033, V-41035, V-41306, and V-41307 from the SQL 2012 Instance STIG.
    .EXAMPLE
    Set-SQLServerAuditing -ScriptFile C:\ConfigureAuditing.sql -ServerName jupitersql1\pluto -InstanceName pluto -TraceFile L:\Logs\Trace_File -MaxFileSize 500 -FileCount 10
    .PARAMETER ScriptFile
    Location of the SQL script file to configure auditing.
    .PARAMETER ServerName
    Hostname of the SQL server in the format hostname\instance (named instance) or hostname (default instance).
    .PARAMETER InstanceName
    Name of the SQL Server instance.
    .PARAMETER TraceFile
    Location of the directory to host the audit files. 
    .PARAMETER MaxFileSize
    Maximum file size in megabytes for each audit file. The minimum is 1 and the maximum is 2,000,000.
    .PARAMETER FileCount
    Maximum number of audit rollover files to maintain. The minimum is 1 and the maximum is 2,147,483,647.
    .COMPONENT
    SQL Server 2012 Database
    .LINK
    http://iase.disa.mil/stigs/app-security/database/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_SQL_Server_2012_V1R7_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database/2015-06-23/finding/V-41402
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41021
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41022
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41027
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41028
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41029
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41030
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41031
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41032
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41033
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41035
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41306
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41307
    #>

    [CmdletBinding()]
    Param 
    (
        [parameter(Mandatory=$true)]
        [string]$ScriptFile,

        [parameter(Mandatory=$true)]
        [string]$ServerName,
        
        [parameter(Mandatory=$true)]
        [string]$InstanceName,

        [parameter(Mandatory=$true)]
        [string]$traceFile,

        [parameter(Mandatory=$true)]
        [ValidateRange(1,2000000)]
        [int32]$maxFileSize,

        [parameter()]
        [ValidateRange(1,2147483647)]
        [int32]$fileCount
    )

    $cleanTraceFilePath = $traceFile.Replace("'","")
    $traceFolder = [System.IO.Path]::GetDirectoryName($cleanTraceFilePath)

    $accounts = Get-SqlServerAccounts -InstanceName $InstanceName
    
    if (!(Test-Path $traceFolder)) {
    
        Write-Output "Folder does not exist - creating $traceFolder for SQL audit logs"
        
        # Code to create the folder

        New-Item $traceFolder -Type Directory

        # Grant permissions to database engine and SQL Agent accounts

        Grant-Permissions -SecurityPrincipal $accounts.SqlServerAccount -Path $traceFolder -Permissions "FullControl"
        Grant-Permissions -SecurityPrincipal $accounts.SqlAgentAccount -Path $traceFolder -Permissions "Read,ReadAndExecute,Write"
    
    }

    else {
    
        Write-Output "$traceFolder already exists, granting permissions to SQL database engine and SQL agent service accounts"
        
        # Grant permission to database engine and sql agent accounts

        Grant-Permissions -SecurityPrincipal $accounts.SqlServerAccount -Path $traceFolder -Permissions "FullControl"
        Grant-Permissions -SecurityPrincipal $accounts.SqlAgentAccount -Path $traceFolder -Permissions "Read,ReadAndExecute,Write"
    
    }

    $traceParam1 = "traceFile=" + $traceFile
    $traceParam2 = "maxFileSize=" + $maxFileSize
    $traceParam3 = "fileCount=" + $fileCount

    $traceParams = $traceParam1, $traceParam2, $traceParam3

    Invoke-Sqlcmd -InputFile $scriptFile -Variable $traceParams -ServerInstance $serverName

    Invoke-Sqlcmd -Query "EXEC master.dbo.STIG_Audits" -ServerInstance $serverName

}

function Harden-SQLServerAuditing {

    <#
    .SYNOPSIS
    Hardens SQL server auditing.
    .DESCRIPTION
    Applies V-40952, V-40953, V-41016, and V-41017 from the SQL 2012 Database Instance STIG.
    .EXAMPLE
    Harden-SQLServerAuditing -ServerName jupitersql1\pluto -InstanceName pluto
    .PARAMETER ServerName
    Hostname of the SQL server in the format hostname\instance (named instance) or hostname (default instance).
    .PARAMETER InstanceName
    Name of the SQL Server instance.
    .COMPONENT
    SQL Server 2012 Database Instance
    .LINK
    http://iase.disa.mil/stigs/app-security/database/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_SQL_Server_2012_V1R7_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-40952
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-40953
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41016
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41017
    #>

    [CmdletBinding()]
    Param 
    (
        [parameter(Mandatory=$true)]
        [string]$ServerName,
        
        [parameter(Mandatory=$true)]
        [string]$InstanceName

    )

    $sqlConnection = New-Object System.Data.SqlClient.SqlConnection "server=$serverName;database=master;Integrated Security=SSPI"
    $sqlConnection.Open()

    $sqlCommand = $sqlConnection.CreateCommand()

    $query = @"
        SELECT DISTINCT
        LEFT(path, (LEN(path) - CHARINDEX('\',REVERSE(path)) + 1)) AS "Audit Path"
        FROM sys.traces
        SELECT log_file_path AS "Audit Path"
        FROM sys.server_file_audits
"@

    $sqlCommand.CommandText = $query

    $sqlReader = $sqlCommand.ExecuteReader()

    # Create an array for results #
    $auditPaths = @()

    while ($sqlReader.Read()) { 
    
        #Push results of command to the array #
        $auditPaths += $sqlReader["Audit Path"]
     
    }

    $sqlConnection.Close()

    # Using results from the array, write PowerShell function to remove local Users group from locations #

    $accounts = Get-SqlServerAccounts -InstanceName $InstanceName

    foreach ($path in $auditPaths) {

        Write-Output "Audit file location is $path"
    
        Disable-Inheritance -Path $path
        
        Grant-Permissions -SecurityPrincipal $env:username -Path $path -Permissions "FullControl"
        
        Revoke-Permissions -SecurityPrincipal "BUILTIN\USERS" -Path $path
        Revoke-Permissions -SecurityPrincipal "CREATOR OWNER" -Path $path
        Revoke-Permissions -SecurityPrincipal "SYSTEM" -Path $path
        
        Grant-Permissions -SecurityPrincipal $accounts.SqlServerAccount -Path $path -Permissions "FullControl"
        Grant-Permissions -SecurityPrincipal $accounts.SqlAgentAccount -Path $path -Permissions "Read,ReadAndExecute,Write"
        
        Revoke-Permissions -SecurityPrincipal "BUILTIN\Administrators" -Path $path
        Grant-Permissions -SecurityPrincipal "BUILTIN\Administrators" -Path $path -Permissions "Read"
        
        Revoke-Permissions -SecurityPrincipal $env:username -Path $path

    }

}

# Generate SSL Certificate #

function New-CertificateSigningRequest {

    <#
    .SYNOPSIS
    Mitigates V-40921, V-40907, V-41308, V-41309, and and V-41310 from the SQL 2012 Database Instance STIG.
    .DESCRIPTION
    Updates an SSL request setup information (.inf) file with the current hostname, then generates a certificate signing request (CSR) in the current working directory. After generation, send the CSR to your certificate authority for processing.
    .PARAM RequestFile
    Location of the SSL request setup information (.inf) file. If not specified, the default file will be that packaged and deployed with the module. 
    .EXAMPLE
    New-CertificateSigningRequest -RequestFile C:\SSLRequest.inf
    .COMPONENT
    SQL Server 2012 Database Instance
    .LINK
    http://iase.disa.mil/stigs/app-security/database/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_SQL_Server_2012_V1R7_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-40921
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41307
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41308
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41309
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41310
    #>
    
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$RequestFile
    )
    
    $hostname = "$env:computername.$env:userdnsdomain"
    $csrFile = $hostname+".txt"
    
    $requestFile = Get-Item $RequestFile
    
    # Add trailing double quote to hostname string
    $hostname = $hostname+'"'

    (Get-Content $requestFile) | ForEach-Object {$_ -Replace '(?<=cn=).*', $hostname} | Set-Content $requestFile

    Set-Location C:\

    certreq -new $requestFile $csrFile

    notepad $csrFile

    Write-Output "CSR is generated and located at C:\$csrFile - send to certificate authority for processing"

}

function Revoke-Permission ($Permission, $SecurityPrinciple) {
    
    $SQLServer.Revoke($Permission, $SecurityPrinciple)

} 

function Remove-Permissions {
    
    <#
    .SYNOPSIS
    Removes specific SQL permission from all accounts and roles except for NT AUTHORITY\SYSTEM, ##MS_PolicyEventProcessingLogin##, and ##MS_PolicyTsqlExecutionLogin##. 
    .DESCRIPTION
    Used to apply checks V-41268 (ControlServer), V-41251 (ViewAnyDatabase), and V-41294 (ViewServerState). 
    .PARAM ServerName
    SQL Server name. For default instances this is the hostname of the server, for named instances this is in teh format hostname\instancename. 
    .PARAM SQLPermission
    Internal name of the SQL server permission. This typically has no spaces. 
    .EXAMPLE
    Remove-Permissions -ServerName jupitersql1\pluto -SQLPermission ViewServerState
    .EXAMPLE
    Remove-Permissions -ServerName jupitersql2 -SQLPermission ViewAnyDatabase
    .COMPONENT
    SQL Server 2012 Database Instance
    .LINK
    http://iase.disa.mil/stigs/app-security/database/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_SQL_Server_2012_V1R7_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41251
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41268
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41294
    #>
    
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$ServerName,

        [parameter(Mandatory=$true)]
        [string]$SQLPermission
    )

    $SQLServer = New-Object "Microsoft.SQLServer.Management.Smo.Server" $serverName
    $permission = [Microsoft.SQLServer.Management.Smo.ServerPermission]::$SQLpermission

    $permissions = $SQLServer.EnumServerPermissions($permission)

    foreach ($item in $permissions) {
        
        $principalName = $item.Grantee
        
        if ($principalName -like "##*" -Or $principalName -like "*SYSTEM") {
            
            Write-Output "$principalName is a default SQL account - not revoking permissions"

        }
        
        else {

            Revoke-Permission $permission $principalName
            Write-Output "Revoked $SQLpermission from $principalName"
        
        }
    
    }
    
}

function Import-CSR {

    <#
    .SYNOPSIS
    Mitigates V-40921, V-40907, V-41308, V-41309, and and V-41310 from the SQL 2012 Database Instance STIG.
    .DESCRIPTION
    Imports a signed certificate signing request into the CERT:\LocalMachine\My certificate store.
    .PARAM Path
    Location of the signed certificate request, generally with a file extension of .cer.
    .EXAMPLE
    Import-CSR -Path C:\certs\signedCSR.cer
    .COMPONENT
    SQL Server 2012 Database Instance
    .LINK
    http://iase.disa.mil/stigs/app-security/database/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_SQL_Server_2012_V1R7_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-40921
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41307
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41308
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41309
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41310
    #>

    [CmdletBinding()]
    Param 
    (
        [parameter(Mandatory=$true)]
        [string]$Path
    )

    certreq -accept $Path

}

function Set-ForceEncryption {

    <#
    .SYNOPSIS
    Mitigates V-40921, V-40907, V-41308, V-41309, and and V-41310 from the SQL 2012 Database Instance STIG.
    .DESCRIPTION
    Sets Force Encryption to true in SQL Server network protocol settings.
    .EXAMPLE
    Set-ForceEncryption
    .COMPONENT
    SQL Server 2012 Database Instance
    .LINK
    http://iase.disa.mil/stigs/app-security/database/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_SQL_Server_2012_V1R7_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-40921
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41307
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41308
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41309
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41310
    #>

    $forceEncryption = Get-WmiObject -Namespace "root\Microsoft\SqlServer\ComputerManagement11" -Class "ServerSettingsGeneralFlag" | Where-Object {$_.FlagName -eq "ForceEncryption"}

    $forceEncryption.SetValue($true)

}

function Grant-ReadAccessToPrivateKey {

    <#
    .SYNOPSIS
    Mitigates V-40921, V-40907, V-41308, V-41309, and V-41310 from the SQL 2012 Database Instance STIG.
    .DESCRIPTION
    Grants the SQL Server database engine service account read access to the appropriate machine key in C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys. This allows the SQL Server database engine service to start successfully on a least-privilege installation after SSL is enabled.
    .PARAM InstanceName
    Name of the instance of SQL Server to be STIG'd. If it is the default instance, use MSSQLSERVER.
    .PARAM CommonName
    Common name (CN) of the certificate used to enable SSL for SQL Server
    .EXAMPLE
    Grant-ReadAccessToPrivateKey -InstanceName "MSSQLSERVER" -CommonName "example.domain.com"
    .COMPONENT
    SQL Server 2012 Database Instance
    .LINK
    http://iase.disa.mil/stigs/app-security/database/Pages/index.aspx
    .LINK
    http://iasecontent.disa.mil/stigs/zip/July2015/U_SQL_Server_2012_V1R7_STIG.zip
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-40921
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41307
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41308
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41309
    .LINK
    https://www.stigviewer.com/stig/microsoft_sql_server_2012_database_instance/2015-06-23/finding/V-41310
    #>

    [CmdletBinding()]
    Param 
    (
    
        [parameter(Mandatory=$true)]
        [string]$InstanceName,

        [parameter(Mandatory=$true)]
        [string]$CommonName

    )

    $accounts = Get-SqlServerAccounts -InstanceName $instanceName

    $sqlServerAccount = $accounts.SqlServerAccount

    $cert = Get-ChildItem -Path CERT:\LocalMachine\My | Where-Object { $_.Subject -match $CommonName }

    $rsaFile = $cert.PrivateKey.CspKeyContainerinfo.UniqueKeyContainername

    $machineKeys = "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\"

    $privateKeyPath = $machineKeys+$rsaFile

    $acl = Get-ACL -Path $privateKeypath

    $permission = $sqlServerAccount,"Read","Allow"

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission

    $acl.AddAccessRule($accessRule)

    Set-Acl -Path $privateKeyPath -AclObject $acl

}