# SharePoint 2013 STIGs
PowerShell scripts to automatically apply the SharePoint 2013, IIS 7 Server, IIS 7 Site, and SQL 2012 Defense Information Systems Agency (DISA) Security Technical Implementation Guides (STIGs) to SharePoint 2013 farms

At the moment only STIGs for IIS 7 (updated for SharePoint 2013) have been completed. SharePoint 2013 and SQL 2012 STIGs will be completed soon. 

## IIS 7 STIGs Installation and Configuration

### Installation
1. Download all of the files in the IIS7 folder from Github and place on a folder on your local machine. For example, ```C:\IIS7STIGs\```.
2. Update the ```$downloadFolder``` variable in ```InstallModule.ps1``` with the path to the folder above. 
3. Run ```InstallModule.ps1```.
4. The module files will be copied to the modules folder for your user account. This is typically ```C:\Users\username\Documents\WindowsPowerShell\Modules\```. If the folder does not exist already it will be created as part of the installation script.

### Verification
Open up the PowerShell console or ISE and run ```Install-Module IIS7STIGs```. The module should load with no errors and its functions should be available for use.

### Configuration
Run ```ApplyIIS7STIGs.ps1``` to apply all of the STIG configuration scripts with the provided IIS Handler Mapping blacklist and request filtering allowed file extensions CSVs. This script can be modified as necessary to remove STIG configurations or to use your own CSV files. 

## Disclaimer
All scripts and supporting files are offered "as is" with no warranty. While I have tested these scripts in my environment, you should always vet and verify these scripts in a test environment before deploying them to production servers.

## License
These scripts are available under the GPLv3 license.