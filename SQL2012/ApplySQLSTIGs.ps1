# Host name of the SQL Server to be STIGed 
$hostname = "SQLSERVER1"
# Instance name of the SQL Server to be STIGed
# If the default instance, set equal to MSSQLSERVER
$instanceName = "MSSQLSERVER"
# Number of max connections for V-41422 
$maxConnections = 3000
# New name of SA account
$newName = "SharePointSA"
# Trace audit file variables
# The folder must already exist or else SQL Server will throw an error creating the trace
$traceFile = "'L:\STIG\STIG_Trace'"
$maxFileSize = 500
$fileCount = 10

if ($instanceName -eq "MSSQLSERVER") {
    
    $sqlServerName = $hostname
    
}

else {

    $sqlServerName = Join-Path -Path $hostname -ChildPath $instanceName

}

## Load SQL 2012 Module ##

Import-Module sqlps -DisableNameChecking
Import-Module SQL2012STIGs

# Import helper permissions functions #
Import-Module permissionsfunctions

$moduleBase = (Get-Module SQL2012STIGs).ModuleBase
$configureAuditingScript = Join-Path -Path $moduleBase -ChildPath "ConfigureAuditing.sql"
$sslRequestInf = Join-Path -Path $moduleBase -ChildPath "SSLRequest.inf"

### Call functions to apply SQL 2012 STIGs ###

Write-Output "`n----- Applying STIGs for SQL 2012 -----"

Write-Output "`n----- Applying V-41422 from SQL 2012 Database -----"

Set-MaxConnections -ServerName $sqlServerName -Limit $maxConnections

Write-Output "`n----- Applying V-40936 from SQL 2012 Instance -----"

Disable-SaAccount -ServerName $sqlServerName

Write-Output "`n----- Configuring SQL Server Auditing -----"

Set-SQLServerAuditing -ScriptFile $configureAuditingScript -ServerName $sqlServerName -InstanceName $instanceName -TraceFile $traceFile -MaxFileSize $maxFileSize -FileCount $fileCount

Write-Output "`n----- Applying V-40944 from SQL 2012 Instance -----"

Set-SQLSoftwareLibrariesPermissions -InstanceName $instanceName

Write-Output "`n----- Applying V-40950 from SQL 2012 Instance -----"

Enable-FileAuditing -InstanceName $instanceName

Write-Output "`n----- Applying V-41037 from SQL 2012 Instance -----"

Rename-SaAccount -ServerName $sqlServerName -NewName $newName

Write-Output "`n----- Applying V-41268 from SQL 2012 Instance -----"

Remove-Permissions -ServerName $sqlServerName -SQLPermission "ControlServer"

Write-Output "`n----- Applying V-41251 from SQL 2012 Instance -----"

Remove-Permissions -ServerName $sqlServerName -SQLPermission "ViewAnyDatabase"

Write-Output "`n----- Applying V-41294 from SQL 2012 Instance -----"

Remove-Permissions -ServerName $sqlServerName -SQLPermission "ViewServerState"

Write-Output "`n----- Applying V-54859 from SQL 2012 Instance -----"

Set-SQLDataRootDirectoryPermissions -InstanceName $instanceName

Write-Output "`n----- Hardening SQL Server Auditing -----"

Harden-SQLServerAuditing -ServerName $sqlServerName -InstanceName $instanceName

Write-Output "`n----- Generate CSR for SQL Server SSL Certificate -----"

New-CertificateSigningRequest -RequestFile $sslRequestInf