# Archived
I no longer maintain this repository as I have not worked professionally with SharePoint since 2015.
# SharePoint 2013 STIGs
PowerShell scripts to automatically apply the [SharePoint 2013](http://iase.disa.mil/stigs/app-security/app-servers/Pages/sharepoint.aspx), [IIS 7 Server](http://iase.disa.mil/stigs/app-security/web-servers/Pages/iis.aspx), [IIS 7 Site](http://iase.disa.mil/stigs/app-security/web-servers/Pages/iis.aspx), and [SQL 2012](http://iase.disa.mil/stigs/app-security/database/Pages/sql.aspx) Defense Information Systems Agency (DISA) Security Technical Implementation Guides (STIGs) to SharePoint 2013 farms.

## SharePoint 2013 STIGs Installation and Configuration

### Installation
1. Download or clone this repository: `git clone https://github.com/alulsh/SharePoint-2013-STIGs.git`
2. Update the `$downloadFolder` variable in `SharePoint2013\InstallModule.ps1` with the path to the `SharePoint2013` directory in the cloned repository. 
3. Run `SharePoint2013\InstallModule.ps1`.
4. The module files will be copied to the modules folder for your user account. This is typically `C:\Users\username\Documents\WindowsPowerShell\Modules\`. If the folder does not exist already it will be created as part of the installation script.

### Verification
Open up the PowerShell console or ISE and run `Install-Module SharePoint2013STIGs`. The module should load with no errors and its functions should be available for use.

### Configuration
Run `SharePoint2013\ApplySharePointSTIGs.ps1` to apply all of the SharePoint STIG configuration PowerShell functions from the module. The variables in this script can be modified as necessary to suit the configuration of your farm.

## IIS 7 STIGs Installation and Configuration

### Installation
1. Download or clone this repository: `git clone https://github.com/alulsh/SharePoint-2013-STIGs.git`
2. Update the `$downloadFolder` variable in `IIS7\InstallModule.ps1` with the path to the `IIS7` directory in the cloned repository. 
3. Run `IIS7\InstallModule.ps1`.
4. The module files will be copied to the modules folder for your user account. This is typically `C:\Users\username\Documents\WindowsPowerShell\Modules\`. If the folder does not exist already it will be created as part of the installation script.

### Verification
Open up the PowerShell console or ISE and run `Install-Module IIS7STIGs`. The module should load with no errors and its functions should be available for use.

### Configuration
Run `IIS7\ApplyIIS7STIGs.ps1` to apply all of the STIG configuration scripts with the provided IIS Handler Mapping blacklist and request filtering allowed file extensions CSVs. This script can be modified as necessary to remove STIG configurations or to use your own CSV files.

## SQL2012 STIGs Installation and Configuration

### Install `PermissionsFunctions` module dependency
1. Download or clone this repository: `git clone https://github.com/alulsh/SharePoint-2013-STIGs.git`
2. Update the `$downloadFolder` variable in `PermissionsFunctions\InstallModule.ps1` with the path to the `PermissionsFunctions` directory in the cloned repository.
3. Run `PermissionsFunctions\InstallModule.ps1`.
4. The module files will be copied to the modules folder for your user account. This is typically `C:\Users\username\Documents\WindowsPowerShell\Modules\`. If the folder does not exist already it will be created as part of the installation script.

### Install the `SQL2012STIGs` Module
1. Update the `$downloadFolder` variable in `SQL2012\InstallModule.ps1` with the path to the `SQL2012` directory in the cloned repository.
2. Run `SQL2012\InstallModule.ps1`.
3. The module files will be copied to the modules folder for your user account. This is typically `C:\Users\username\Documents\WindowsPowerShell\Modules\`. If the folder does not exist already it will be created as part of the installation script.

### Verification
Open up the PowerShell console or ISE and run `Install-Module PermissionsFunctions` and `Install-Module SQL2012STIGs`. The modules should load with no errors and their functions should be available for use.

### Configuration
Run `SQL2012\ApplySQLSTIGs.ps1` to apply all of the STIG configuration scripts for SQL 2012. This script can be modified as necessary to change or remove specific STIG configurations.

## Disclaimer
All scripts and supporting files are offered "as is" with no warranty. While I have tested these scripts in my environment, you should always vet and verify these scripts in a test environment before deploying them to production servers.

It is highly recommended to take snapshots before applying these STIGs in a virtualized environment. All web, application, and database servers in the entire SharePoint farm **MUST** be powered off while taking these snapshots in order to ensure a successful restore. 

## License
These scripts are available under the GPLv3 license.