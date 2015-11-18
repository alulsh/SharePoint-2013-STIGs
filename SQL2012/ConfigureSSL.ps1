$csr = "C:\Certs\SignedCSR.cer"
$InstanceName = "MSSQLSERVER"

Import-Module SQL2012STIGs

Import-CSR -Path $csr

## Manually configure SSL Certificate and restart SQL Service ##

Set-ForceEncryption

Grant-ReadAccessToPrivateKey -InstanceName $InstanceName -CommonName $CommonName