param([string]$debug="SilentContinue")
$DebugPreference = $debug

#---------------------------------------------------------------------------------------------
#                      Utils  C L A S S
#---------------------------------------------------------------------------------------------

class Utils{

    InvokeMSIExec([string]$Args) {
       
        If($DebugPreference = "Continue") {Write-Debug "Invoke-MSIExec" -ForegroundColor DarkGray}

        Write-Verbose ($Args -join " ")
        # Note: The Out-Null forces the function to wait until the prior process completes, nifty
        & (Join-Path $env:SystemRoot 'System32\msiexec.exe') $Args | Out-Null
    }
    
    InvokeProcess($Exec, $Args) {

    If($DebugPreference = "Continue") {Write-Debug "Invoke-Process $Exec $Args" -ForegroundColor DarkGray}

    Write-host "Command to execute ["$Exec $Args" ]" -foreground "green"

    $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processStartInfo.RedirectStandardError = $true
    $processStartInfo.RedirectStandardOutput = $true
    $processStartInfo.UseShellExecute = $false

    $processStartInfo.FileName = $Exec
    $processStartInfo.Arguments = $Args

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processStartInfo
    $process.Start() | Out-Null
    $process.WaitForExit()
    $standardError = $process.StandardError.ReadToEnd()
    if ($process.ExitCode) {
       Write-Error $standardError
    } else {
        Write-Host $standardError
    }
}

    [string]GetValue([string]$Prompt, [string]$Default){

        $value = Read-Host -Prompt "$Prompt [$($Default)]"
        $value = ($Default, $value)[[bool]$value]    
        Write-host "Set value ["$value" ]" -foreground "green"
        return $value
    }
}

#---------------------------------------------------------------------------------------------
#                      OpenSSLUtils  C L A S S
#---------------------------------------------------------------------------------------------

class OpenSSLUtils{

    [string]$opensslFolder
    static [string]$defaultOpenSSLBinFolder = "C:\oss\OpenSSL\bin"
    [string]$openssl
    [Utils]$Utils

    SetOpenSSLConfigFile(){

        If($DebugPreference = "Continue") {Write-host "OpenSSLUtils::SetOpenSSLConfigFile" -ForegroundColor DarkGray}

        $this.opensslCfg = Join-Path $this.opensslBinFolder "openssl.cfg"
        Write-host "Searching openssl config file at $this.opensslCfg" -ForegroundColor cyan

        if (-not (Test-Path $this.opensslCfg)){
            Write-host "Configuration not found, creating a new one" -ForegroundColor cyan
            New-Item $this.opensslCfg -ItemType file

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                '        
HOME			= .
RANDFILE		= $ENV::HOME/.rnd

oid_section		= new_oids




[ new_oids ]



tsa_policy1 = 1.2.3.4.1
tsa_policy2 = 1.2.3.4.5.6
tsa_policy3 = 1.2.3.4.5.7

[ ca ]
default_ca	= CA_default		# The default ca section


[ CA_default ]

dir		= ./demoCA		
certs		= $dir/certs		
crl_dir		= $dir/crl		
database	= $dir/index.txt	
#unique_subject	= no			
					
new_certs_dir	= $dir/newcerts		

certificate	= $dir/cacert.pem 	
serial		= $dir/serial 		
crlnumber	= $dir/crlnumber	
					
crl		= $dir/crl.pem 		
private_key	= $dir/private/cakey.pem
RANDFILE	= $dir/private/.rand	

x509_extensions	= usr_cert		


name_opt 	= ca_default		
cert_opt 	= ca_default		


default_days	= 365			
default_crl_days= 30			
default_md	= default		
preserve	= no			

policy		= policy_match

[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional


[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

[ req ]
default_bits		= 2048
default_keyfile 	= privkey.pem
distinguished_name	= req_distinguished_name
attributes		= req_attributes
x509_extensions	= v3_ca	# The extentions to add to the self signed cert


string_mask = utf8only

[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= IE
countryName_min			= 2
countryName_max			= 2

stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= Some-State

localityName			= Locality Name (eg, city)

0.organizationName		= Organization Name (eg, company)
0.organizationName_default	= Internet Widgits Pty Ltd


organizationalUnitName		= Organizational Unit Name (eg, section)

commonName			= Common Name (e.g. server FQDN or YOUR name)
commonName_max			= 64

emailAddress			= Email Address
emailAddress_max		= 64


[ req_attributes ]
challengePassword		= A challenge password
challengePassword_min		= 4
challengePassword_max		= 20

unstructuredName		= An optional company name

[ usr_cert ]


basicConstraints=CA:FALSE
nsComment			= "OpenSSL Generated Certificate"

subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer


[ v3_req ]

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[ v3_ca ]

subjectKeyIdentifier=hash

authorityKeyIdentifier=keyid:always,issuer
basicConstraints = CA:true
[ crl_ext ]

authorityKeyIdentifier=keyid:always

[ proxy_cert_ext ]
basicConstraints=CA:FALSE
nsComment			= "OpenSSL Generated Certificate"

authorityKeyIdentifier=keyid,issuer

proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo

[ tsa ]

default_tsa = tsa_config1	# the default TSA section

[ tsa_config1 ]

dir		= ./demoCA		
serial		= $dir/tsaserial	
crypto_device	= builtin		
signer_cert	= $dir/tsacert.pem 	
					
certs		= $dir/cacert.pem	
					
signer_key	= $dir/private/tsakey.pem 

default_policy	= tsa_policy1		
					
other_policies	= tsa_policy2, tsa_policy3	
digests		= md5, sha1		
accuracy	= secs:1, millisecs:500, microsecs:100	
clock_precision_digits  = 0	
ordering		= yes	
				
tsa_name		= yes	
				
ess_cert_id_chain	= no	
				

        ' | Out-File -FilePath $this.opensslCfg -Append

            $env:OPENSSL_CONF = $this.opensslCfg
            $env:RANDFILE=".rnd"

            Write-Host "Set OPENSSL_CONF variable to $this.opensslCfg" -foregroundColor Green
        }
    }

    [string]OpenSSLCommand(){

        If($DebugPreference = "Continue") {Write-host "OpenSSLUtils::OpenSSLCommand" -ForegroundColor DarkGray}

        if (-not(Test-Path $this.opensslFolder)){
            $this.opensslFolder = Utils.GetValue ("Input OpenSSL bin folder", $this.defaultOpenSSLBinFolder)
            $this.openssl = Join-Path $this.opensslFolder "openssl.exe"
        }
        return $this.openssl
    }

    OpenSSLUtils([string]$sslFolder){
        $this.opensslFolder = $sslFolder
        $this.Utils = [Utils]::new()
    }
}

class MongoDBUtils{

    [string]$defaultMongoDBMSIFileSource
    [string]$defaultMongoDBMSIFileTarget
    [string]$mongoDBMSIFileSource
    [string]$mongoDBMSIFileTarget
    [string]$defaultFileName = 'mongodb-keyfile.key'
    [string]$filenameKeyFile
    [string]$rootFolder

    [OpenSSLUtils]$openSSLUtils
    [Utils]$Utils
    
    GetMongoDb(){
    
    If($DebugPreference = "Continue") {Write-Debug "MongoDBUtils::GetMongoDb" -ForegroundColor DarkGray}

        $this.mongoDBMSIFileSource = Utils.GetValue( "Enter source msi file", $this.defaultMongoDBMSIFileSource)

        $this.mongoDBMSIFileTarget = Utils.GetValue "Enter target msi file name" $this.defaultMongoDBMSIFileTarget

        if (-Not (Test-Path $this.mongoDBMSIFileTarget)){
            Write-host "Downloading MongoDB installation MSI File..." -foreground "green"
            curl -o $this.mongoDBMSIFileTarget $this.mongoDBMSIFileSource
        }

        Write-host "Create MongoDB Server Folder $this.mongoDBTargetFolder" -foreground "green"
        New-Item -ItemType directory -path $this.mongoDBTargetFolder
    
        $this.mongoDBTargetFolder = '"' + $this.mongoDBTargetFolder + '"'

        $arguments = "/quiet /passive /i $this.mongoDBMSIFileTarget INSTALLLOCATION=$this.mongoDBTargetFolder ADDLOCAL=$this.mongoDBAddLocal"

        Utils.InvokeMSIExec /a $this.mongoDBMSIFileTarget /qb TARGETDIR=$this.smongoDBTargetFolder

        Write-host "MongoDB installed" -ForegroundColor "cyan"
    }

    SetMongoDbKeyFile(){

    If($DebugPreference = "Continue") {Write-Host "Set-MongoDb-KeyFile" -ForegroundColor DarkGray}

    $this.filenameKeyFile = Get-Value "Input MongoDB KeyFile" $this.defaultFileName

	$this.filenameKeyFile = Join-Path $this.rootFolder $this.filenameKeyFile

	Write-host "Selected Keyfile ["$this.filenameKeyFile" ]" -foreground "green" 
	
	$openssl = $this.openSSLUtils.OpenSSLCommand
    
	$arguments = "rand -base64 756 -out $this.filenameKeyFile"
	
	if (Test-path $openssl){

        $this.filenameKey = $this.Utils.InvokeProcess($openssl, $arguments)
        
        if (Test-path $this.filenameKeyFile){
            Write-host "Created KeyFile at ["$this.filenameKeyFile"]" -foreground "cyan"
        }
        Else {
            Write-host "ERROR: KeyFile not created" -foregroundColor Red
            Exit
        }
	}
	Else
	{
		Write-host "Couldn't find OpenSSL" -foreground "red"
        Exit
	}
}


    MongoDBUtils([string]$dftMongoDBMSIFileSource,[string]$dftMongoDBMSIFileTarget,[OpenSSLUtils]$openSSLUtl,[string]$root){
        $this.defaultMongoDBMSIFileSource = $dftMongoDBMSIFileSource
        $this.defaultMongoDBMSIFileTarget = $dftMongoDBMSIFileTarget
        $this.openSSL = $openSSLUtl
        $this.rootFolder = $root
        $this.Utils = [Utils]::new()
    }
}

class MongoInstaller{
    #---------------------------------------------------------------------------------------------
    #                       D E F A U L T    V A L U E S
    #---------------------------------------------------------------------------------------------

    static [string]$defaultDownloadMongoDB = 'N'
    static [string]$defaultCreateKeyFile = 'Y'
    static [string]$defaultFileName = 'mongodb-keyfile.key'
    static [string]$defaultRemoveInstances = 'Y'
    static [string]$defaultRemoveOldData = 'Y'
    static [string]$defaultCreateWindowsServices = 'Y'
    static [string]$defaultCreateReplicaSet = 'Y'
    static [string]$defaultCreateUsers = 'Y'
    static [string]$defaultReplicaSetName = 'TestRS'
    static [string]$defaultRootFolder = 'C:\QueueSystem'
    static [string]$defaultServicePrefix = 'mongodbX'
    static [int]$defaultInitialPort = 27100
    static [int]$defaultNumberOfNodes = 4
    static [string]$defaultOpenSSLBinFolder = "C:\oss\OpenSSL\bin"
    static [string]$defaultCreateCA = 'Y'
    static [string]$defaultCreateCert = 'Y'
    static [string]$defaultCertFile = "mongoRS.pem"
    static [string]$dn_prefix="/C=IE/ST=D/L=Accenture/O=Technology"
    static [string]$ou_member="MyServers"
    static [string]$ou_client="MyClients"
    static [string]$defaultMongoDBMSIFileSource = "https://fastdl.mongodb.org/win32/mongodb-win32-x86_64-2008plus-ssl-3.4.2-signed.msi"
    static [string]$defaultMongoDBMSIFileTarget = "mongodb.msi"
    static [string]$msiexec = "msiexec.exe"
    static [string]$openssl = "openssl"
    static [string]$mongoDBTargetFolder = "C:\QueueSystem\Server"
    static [string]$mongoDBAddLocal = '"ALL"'
    static [string]$opensslBinFolder = ""
    static [string]$openssl = ""
    static [string]$opensslCfg 

    [Utils]$Utils 
    
    [MongoDBUtils]$MongoDB

    [OpenSSLUtils]$OpenSSL 



}
#---------------------------------------------------------------------------------------------
#                       D E F A U L T    V A L U E S
#---------------------------------------------------------------------------------------------

$defaultDownloadMongoDB = 'N'
$defaultCreateKeyFile = 'Y'
$defaultFileName = 'mongodb-keyfile.key'
$defaultRemoveInstances = 'Y'
$defaultRemoveOldData = 'Y'
$defaultCreateWindowsServices = 'Y'
$defaultCreateReplicaSet = 'Y'
$defaultCreateUsers = 'Y'
$defaultReplicaSetName = 'TestRS'
$defaultRootFolder = 'C:\QueueSystem'
$defaultServicePrefix = 'mongodbX'
$defaultInitialPort = 27100
$defaultNumberOfNodes = 4
$defaultOpenSSLBinFolder = "C:\oss\OpenSSL\bin"
$defaultCreateCA = 'Y'
$defaultCreateCert = 'Y'
$defaultCertFile = "mongoRS.pem"
$dn_prefix="/C=IE/ST=D/L=Accenture/O=Technology"
$ou_member="MyServers"
$ou_client="MyClients"
$defaultMongoDBMSIFileSource = "https://fastdl.mongodb.org/win32/mongodb-win32-x86_64-2008plus-ssl-3.4.2-signed.msi"
$defaultMongoDBMSIFileTarget = "mongodb.msi"

$msiexec = "msiexec.exe"
$openssl = "openssl"
$mongoDBTargetFolder = "C:\QueueSystem\Server"
$mongoDBAddLocal = '"ALL"'
$opensslBinFolder = ""
$openssl = ""

#---------------------------------------------------------------------------------------------
#                       function Set-OpenSSL-ConfigFile
#---------------------------------------------------------------------------------------------

function Set-OpenSSL-ConfigFile([string]$opensslFolder){

    If($DebugPreference = "Continue") {Write-host "Set-OpenSSL-ConfigFile $opensslFolder" -ForegroundColor DarkGray}

    $opensslCfg = Join-Path $opensslFolder "openssl.cfg"
    Write-host "Searching openssl config file at $opensslCfg" -ForegroundColor cyan

    if (-not (Test-Path $opensslCfg)){
        Write-host "Configuration not found, creating a new one" -ForegroundColor cyan
        New-Item $opensslCfg -ItemType file

        '        
HOME			= .
RANDFILE		= $ENV::HOME/.rnd

oid_section		= new_oids




[ new_oids ]



tsa_policy1 = 1.2.3.4.1
tsa_policy2 = 1.2.3.4.5.6
tsa_policy3 = 1.2.3.4.5.7

[ ca ]
default_ca	= CA_default		# The default ca section


[ CA_default ]

dir		= ./demoCA		
certs		= $dir/certs		
crl_dir		= $dir/crl		
database	= $dir/index.txt	
#unique_subject	= no			
					
new_certs_dir	= $dir/newcerts		

certificate	= $dir/cacert.pem 	
serial		= $dir/serial 		
crlnumber	= $dir/crlnumber	
					
crl		= $dir/crl.pem 		
private_key	= $dir/private/cakey.pem
RANDFILE	= $dir/private/.rand	

x509_extensions	= usr_cert		


name_opt 	= ca_default		
cert_opt 	= ca_default		


default_days	= 365			
default_crl_days= 30			
default_md	= default		
preserve	= no			

policy		= policy_match

[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional


[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

[ req ]
default_bits		= 2048
default_keyfile 	= privkey.pem
distinguished_name	= req_distinguished_name
attributes		= req_attributes
x509_extensions	= v3_ca	# The extentions to add to the self signed cert


string_mask = utf8only

[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= IE
countryName_min			= 2
countryName_max			= 2

stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= Some-State

localityName			= Locality Name (eg, city)

0.organizationName		= Organization Name (eg, company)
0.organizationName_default	= Internet Widgits Pty Ltd


organizationalUnitName		= Organizational Unit Name (eg, section)

commonName			= Common Name (e.g. server FQDN or YOUR name)
commonName_max			= 64

emailAddress			= Email Address
emailAddress_max		= 64


[ req_attributes ]
challengePassword		= A challenge password
challengePassword_min		= 4
challengePassword_max		= 20

unstructuredName		= An optional company name

[ usr_cert ]


basicConstraints=CA:FALSE
nsComment			= "OpenSSL Generated Certificate"

subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer


[ v3_req ]

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[ v3_ca ]

subjectKeyIdentifier=hash

authorityKeyIdentifier=keyid:always,issuer
basicConstraints = CA:true
[ crl_ext ]

authorityKeyIdentifier=keyid:always

[ proxy_cert_ext ]
basicConstraints=CA:FALSE
nsComment			= "OpenSSL Generated Certificate"

authorityKeyIdentifier=keyid,issuer

proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo

[ tsa ]

default_tsa = tsa_config1	# the default TSA section

[ tsa_config1 ]

dir		= ./demoCA		
serial		= $dir/tsaserial	
crypto_device	= builtin		
signer_cert	= $dir/tsacert.pem 	
					
certs		= $dir/cacert.pem	
					
signer_key	= $dir/private/tsakey.pem 

default_policy	= tsa_policy1		
					
other_policies	= tsa_policy2, tsa_policy3	
digests		= md5, sha1		
accuracy	= secs:1, millisecs:500, microsecs:100	
clock_precision_digits  = 0	
ordering		= yes	
				
tsa_name		= yes	
				
ess_cert_id_chain	= no	
				

        ' | Out-File -FilePath $opensslCfg -Append

        $env:OPENSSL_CONF = $opensslCfg
        $env:RANDFILE=".rnd"

        Write-Host "Set OPENSSL_CONF variable to $opensslCfg" -foregroundColor Green
        #Write-Host $env:OPENSSL_CONF
    }
}


#---------------------------------------------------------------------------------------------
#                       function Invoke-MSIExec
#---------------------------------------------------------------------------------------------

function Invoke-MSIExec {
    <#
    .SYNOPSIS
    Invokes msiexec.exe
    .DESCRIPTION
    Runs msiexec.exe, passing all the arguments that get passed to `Invoke-MSIExec`.
    .EXAMPLE
    Invoke-MSIExec /a C:\temp\EwsManagedApi.MSI /qb TARGETDIR=c:\Scripts\EWSAPI
    Runs `/a C:\temp\EwsManagedApi.MSI /qb TARGETDIR=c:\temp\EWSAPI`, which extracts the contents of C:\temp\EwsManagedApi.MSI into c:\temp\EWSAPI
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments=$true)]
        $Args
    )
        
    If($DebugPreference = "Continue") {Write-Debug "Invoke-MSIExec" -ForegroundColor DarkGray}

    Write-Verbose ($Args -join " ")
    # Note: The Out-Null forces the function to wait until the prior process completes, nifty
    & (Join-Path $env:SystemRoot 'System32\msiexec.exe') $Args | Out-Null
}

#---------------------------------------------------------------------------------------------
#                       function Invoke-Process
#---------------------------------------------------------------------------------------------

function Invoke-Process($Exec, $Args) {
    <#
    .SYNOPSIS
    Invokes a process
    .DESCRIPTION
    Runs a process, passing all the arguments that get passed to `Invoke-Process`.
    .EXAMPLE
    Invoke-Process mongod --ssl
    Runs `mongod --ssl`
    #>
        
    If($DebugPreference = "Continue") {Write-Debug "Invoke-Process $Exec $Args" -ForegroundColor DarkGray}

    Write-host "Command to execute ["$Exec $arguments" ]" -foreground "green"

    $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processStartInfo.RedirectStandardError = $true
    $processStartInfo.RedirectStandardOutput = $true
    $processStartInfo.UseShellExecute = $false

    $processStartInfo.FileName = $Exec
    $processStartInfo.Arguments = $Args

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processStartInfo
    $process.Start() | Out-Null
    $process.WaitForExit()
    $standardError = $process.StandardError.ReadToEnd()
    if ($process.ExitCode) {
       Write-Error $standardError
    } else {
        Write-Host $standardError
    }
}

#---------------------------------------------------------------------------------------------
#                     function Get-Value
#---------------------------------------------------------------------------------------------

function Get-Value([string]$Prompt, [string]$Default){

    $value = Read-Host -Prompt "$Prompt [$($Default)]"
    $value = ($Default, $value)[[bool]$value]    
    Write-host "Set value ["$value" ]" -foreground "green"
    return $value
}

#---------------------------------------------------------------------------------------------
#                     function Get-MongoDb
#---------------------------------------------------------------------------------------------

function Get-MongoDb{
    
    If($DebugPreference = "Continue") {Write-Debug "Get-MongoDb" -ForegroundColor DarkGray}

    $mongoDBMSIFileSource = Get-Value "Enter source msi file" $defaultMongoDBMSIFileSource

    $mongoDBMSIFileTarget = Get-Value "Enter target msi file name" $defaultMongoDBMSIFileTarget

    if (-Not (Test-Path $mongoDBMSIFileTarget)){
        Write-host "Downloading MongoDB installation MSI File..." -foreground "green"
        curl -o $mongoDBMSIFileTarget $mongoDBMSIFileSource
    }

    Write-host "Create MongoDB Server Folder $mongoDBTargetFolder" -foreground "green"
    New-Item -ItemType directory -path $mongoDBTargetFolder
    
    $mongoDBTargetFolder = '"' + $mongoDBTargetFolder + '"'

    $arguments = "/quiet /passive /i $mongoDBMSIFileTarget INSTALLLOCATION=$mongoDBTargetFolder ADDLOCAL=$mongoDBAddLocal"

    Invoke-MSIExec /a $mongoDBMSIFileTarget /qb TARGETDIR=$mongoDBTargetFolder

    Write-host "MongoDB installed" -ForegroundColor "cyan"
}

#---------------------------------------------------------------------------------------------
#                     function Get-MongoDb-KeyFile
#---------------------------------------------------------------------------------------------

function Set-MongoDb-KeyFile{

    If($DebugPreference = "Continue") {Write-Host "Set-MongoDb-KeyFile" -ForegroundColor DarkGray}

    $filenameKeyFile = Get-Value "Input MongoDB KeyFile" $defaultFileName

	$filenameKeyFile = Join-Path $rootFolder $filenameKeyFile

	Write-host "Selected Keyfile ["$filenameKeyFile" ]" -foreground "green" 
	
	$opensslBinFolder = Get-Value "Input OpenSSL bin folder" $defaultOpenSSLBinFolder

	$openssl = Join-Path $opensslBinFolder "openssl.exe"
    
	$arguments = "rand -base64 756 -out $filenameKeyFile"
	
	if (Test-path $openssl){
		
        #Invoke-Process $openssl $arguments
         
        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.RedirectStandardError = $true
        $processStartInfo.RedirectStandardOutput = $true
        $processStartInfo.UseShellExecute = $false

        $processStartInfo.FileName = $openssl
        $processStartInfo.Arguments = $arguments

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processStartInfo
        $process.Start() | Out-Null
        $process.WaitForExit()
        $standardError = $process.StandardError.ReadToEnd()
        if ($process.ExitCode) {
           Write-Error $standardError
        } else {
            Write-Host $standardError
        }
                  
        if (Test-path $filenameKeyFile){
            Write-host "Created KeyFile at ["$filenameKeyFile"]" -foreground "cyan"
        }
        Else {
            Write-host "ERROR: KeyFile not created" -foregroundColor Red
            Exit
        }
	}
	Else
	{
		Write-host "Couldn't find OpenSSL" -foreground "red"
        Exit
	}
}

#---------------------------------------------------------------------------------------------
#                     function Generate-Root-CA
#---------------------------------------------------------------------------------------------

function Generate-Root-CA([string]$rootFolder){
    
    If($DebugPreference = "Continue") {Write-Debug "Generate-Root-CA $rootFolder" -ForegroundColor DarkGray}

    $opensslBinFolder = Get-Value "Input OpenSSL bin folder" $defaultOpenSSLBinFolder

	$openssl = Join-Path $opensslBinFolder "openssl.exe"
        
    if (Test-path $openssl){

        Set-OpenSSL-ConfigFile $opensslBinFolder
        
        $CAFile = Join-Path $rootFolder "root-ca.key"

        $arguments = "genrsa -out $CAFile 2048"

        #Invoke-Process $openssl $arguments

        Write-host "Command to execute ["$Exec $arguments" ]" -foreground "green"
         
        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.RedirectStandardError = $true
        $processStartInfo.RedirectStandardOutput = $true
        $processStartInfo.UseShellExecute = $false

        $processStartInfo.FileName = $openssl
        $processStartInfo.Arguments = $arguments

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processStartInfo
        $process.Start() | Out-Null
        $process.WaitForExit()
        $standardError = $process.StandardError.ReadToEnd()
        if ($process.ExitCode) {
           Write-Error $standardError
        } else {
            Write-Host $standardError
        }
                  
        if (Test-path $CAFile){
            Write-host "Created root-ca file at ["$CAFile"]" -foreground "cyan"
            return $CAFile
        }
        Else {
            Write-host "ERROR: KeyFile not created" -foregroundColor Red
            Exit
        }
	}
	Else
	{
		Write-host "Couldn't find OpenSSL" -foreground "red"
        Exit
	}

}

#---------------------------------------------------------------------------------------------
#                     function Generate-Root-CA-crt
#---------------------------------------------------------------------------------------------

function Generate-Root-CA-crt([string]$rootFolder,[string]$CAFile){

    If($DebugPreference = "Continue") {Write-Debug "Generate-Root-CA-crt $rootFolder $CAFile" -ForegroundColor DarkGray}

    $opensslBinFolder = Get-Value "Input OpenSSL bin folder" $defaultOpenSSLBinFolder

	$openssl = Join-Path $opensslBinFolder "openssl.exe"
        
    if (Test-path $openssl){

        $CAPubFile = Join-Path $rootFolder "root-ca.crt"
        
        #Invoke-Process $openssl $arguments

        
        $subject = "/C=IE/ST=D/L=Accenture/O=Technology/CN=ROOTCA"
        $args = "req -new -x509 -days 3650 -key $CAFile -out $CAPubFile" + ' -subj "' + $subject + '"'
        $arguments = $args
        
        Write-host "Command to execute ["$openssl $arguments" ]" -foreground "green"
        
        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.RedirectStandardError = $true
        $processStartInfo.RedirectStandardOutput = $true
        $processStartInfo.UseShellExecute = $false
        $processStartInfo.FileName = $openssl
        $processStartInfo.Arguments = $arguments
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processStartInfo
        $process.Start() | Out-Null
        $process.WaitForExit()
        $standardError = $process.StandardError.ReadToEnd()
        if ($process.ExitCode) {
            Write-Error $standardError
        } else {
            Write-Host $standardError
        }
        Write-host "Created CA public file at ["$CAPubFile"]" -foreground "cyan"
        }
	Else
	{
		Write-host "Couldn't find OpenSSL" -foreground "red"
        Exit
	}
}

#---------------------------------------------------------------------------------------------
#                     function Move-CA-Files
#---------------------------------------------------------------------------------------------

function Move-CA-Files([string]$rootFolder){
    
    If($DebugPreference = "Continue") {Write-Debug "Move-CA-Files $rootFolder" -ForegroundColor DarkGray}

    Write-host "Creating folder $rootFolder\RootCA"

    $rootCA = Join-Path $rootFolder "RootCA"
    New-Item -ItemType directory -path $rootCA
    $tempFile = Join-Path $rootCA "ca.db.index"
    New-Item $tempFile -ItemType file

    Move-Item "root-ca*.*" $rootCA
    
    $random = Get-Random -Maximum 1000 -Minimum 1
    $tempFile = Join-Path $rootCA "ca.db.rand"
    New-Item $tempFile -ItemType file     
	$random | Out-File -FilePath $tempFile -Append

    $tempFile = Join-Path $rootCA "ca.db.serial"
    New-Item $tempFile -ItemType file     
	"01" | Out-File -FilePath $tempFile -Append

    $tempFolder = Join-Path $rootCA "ca.db.certs"
    New-Item -ItemType directory -path $tempFolder

    # Generate CA config

    $CACfgFile = Join-Path $rootCA "root-ca.cfg"
    New-Item $CACfgFile -ItemType file

    $signingCA = Join-Path $rootFolder "SigningCA"
    New-Item -ItemType directory -path $signingCA

        "[ RootCA ]
    dir             = $rootCA
    certs           = $dir/ca.db.certs
    database        = $dir/ca.db.index
    new_certs_dir   = $dir/ca.db.certs
    certificate     = $dir/root-ca.crt
    serial          = $dir/ca.db.serial
    private_key     = $dir/root-ca.key
    RANDFILE        = $dir/ca.db.rand
    default_md      = sha256
    default_days    = 365
    default_crl_days= 30
    email_in_dn     = no
    unique_subject  = no
    policy          = policy_match

    [ SigningCA ]
    dir             = $signingCA
    certs           = $signingCA\ca.db.certs
    database        = $signingCA\ca.db.index
    new_certs_dir   = $signingCA\ca.db.certs
    certificate     = $signingCA\signing-ca.crt
    serial          = $signingCA\ca.db.serial
    private_key     = $signingCA\signing-ca.key
    RANDFILE        = $signingCA\ca.db.rand
    default_md      = sha256
    default_days    = 365
    default_crl_days= 30
    email_in_dn     = no
    unique_subject  = no
    policy          = policy_match

    [ policy_match ]
    countryName     = match
    stateOrProvinceName = match
    localityName            = match
    organizationName    = match
    organizationalUnitName  = optional
    commonName      = supplied
    emailAddress        = optional

    [ v3_req ]
    basicConstraints = CA:FALSE
    keyUsage = nonRepudiation, digitalSignature, keyEncipherment

    [ v3_ca ]
    subjectKeyIdentifier=hash
    authorityKeyIdentifier=keyid:always,issuer:always
    basicConstraints = CA:true" | Out-File -FilePath $CACfgFile -Append
}

#---------------------------------------------------------------------------------------------
#                     function Generate-CA-Files
#---------------------------------------------------------------------------------------------

function Generate-CA-Files([string]$rootFolder){
    
    If($DebugPreference = "Continue") {Write-Debug "Generate-CA-Files $rootFolder" -ForegroundColor DarkGray}

    $CAFile = Generate-Root-CA $rootFolder

    $pub = Generate-Root-CA-crt $rootFolder $CAFile
    
    Move-CA-Files $rootFolder

    return $pub

}

#---------------------------------------------------------------------------------------------
#                     function Generate-Signing-Key
#---------------------------------------------------------------------------------------------

function Generate-Signing-Key([string]$rootFolder){

    If($DebugPreference = "Continue") {Write-Debug "Generate-Signing-Key $rootFolder" -ForegroundColor DarkGray}

    $opensslBinFolder = Get-Value "Input OpenSSL bin folder" $defaultOpenSSLBinFolder

	$openssl = Join-Path $opensslBinFolder "openssl.exe"
        
    if (Test-path $openssl){
        Write-host "Creating a signing key..."

        $CASigningKey = Join-Path $rootFolder "signing-ca.key"
        $arguments = "genrsa -out $CASigningKey 2048  "

        #Invoke-Process $openssl $arguments

        Write-host "Command to execute ["$openssl $arguments" ]" -foreground "green"
         
        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.RedirectStandardError = $true
        $processStartInfo.RedirectStandardOutput = $true
        $processStartInfo.UseShellExecute = $false

        $processStartInfo.FileName = $openssl
        $processStartInfo.Arguments = $arguments

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processStartInfo
        $process.Start() | Out-Null
        $process.WaitForExit()
        $standardError = $process.StandardError.ReadToEnd()
        if ($process.ExitCode) {
           Write-Error $standardError
        } else {
            Write-Host $standardError
        }
                  
        if (Test-path $CASigningKey){
            Write-host "Created signing key file at ["$CASigningKey"]" -foreground "cyan"
            return $CASigningKey
        }
        Else {
            Write-host "ERROR: signing key not created" -foregroundColor Red
            Exit
        }
	}
	Else
	{
		Write-host "Couldn't find OpenSSL" -foreground "red"
        Exit
	}
}

#---------------------------------------------------------------------------------------------
#                     function Generate-Signing-Csr
#---------------------------------------------------------------------------------------------

function Generate-Signing-Csr([string]$rootFolder,[string]$CASigningKey){
    
    If($DebugPreference = "Continue") {Write-Debug "Generate-Signing-Csr $rootFolder $CASigningKey" -ForegroundColor DarkGray}

    $opensslBinFolder = Get-Value "Input OpenSSL bin folder" $defaultOpenSSLBinFolder
    
	$openssl = Join-Path $opensslBinFolder "openssl.exe"
        
    if (Test-path $openssl){

        $CAPubFile = Join-Path $rootFolder "root-ca.crt"

        #Invoke-Process $openssl $arguments

        
        $SigningCACSR = Join-Path $rootFolder "Signing-ca.csr"
        $subject = "/C=IE/ST=D/L=Accenture/O=Technology/CN=CA-SIGNER"
        $args = "req -new -days 10000 -key  $CASigningKey -out $SigningCACSR" + ' -subj "' + $subject + '"' 
        $arguments = $args

        Write-host "Command to execute ["$openssl $arguments" ]" -foreground "green"

        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.RedirectStandardError = $true
        $processStartInfo.RedirectStandardOutput = $true
        $processStartInfo.UseShellExecute = $false
        $processStartInfo.FileName = $openssl
        $processStartInfo.Arguments = $arguments
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processStartInfo
        $process.Start() | Out-Null
        $process.WaitForExit()
        $standardError = $process.StandardError.ReadToEnd()
        if ($process.ExitCode) {
            Write-Error $standardError
        } else {
            Write-Host $standardError
            
        }
        if (Test-path $SigningCACSR){
            Write-host "Created signing csr file at ["$SigningCACSR"]" -foreground "cyan"
        }
        Else {
            Write-host "ERROR: signing csr not created" -foregroundColor Red
            Exit        
        }
    }

	Else
	{
		Write-host "Couldn't find OpenSSL" -foreground "red"
        Exit
	}
}

#---------------------------------------------------------------------------------------------
#                     function Generate-Signing-Crt
#---------------------------------------------------------------------------------------------

function Generate-Signing-Crt([string]$rootFolder){
    
    If($DebugPreference = "Continue") {Write-Debug "Generate-Signing-Crt $rootFolder" -ForegroundColor DarkGray}

    $opensslBinFolder = Get-Value "Input OpenSSL bin folder" $defaultOpenSSLBinFolder

	$openssl = Join-Path $opensslBinFolder "openssl.exe"
        
    if (Test-path $openssl){

        $CAPubFile = Join-Path $rootFolder "root-ca.crt"
        
        #Invoke-Process $openssl $arguments

        
        $SigningCACRT = Join-Path $rootFolder "Signing-ca.crt"
        $arguments = "ca -batch -name RootCA -config $CACfgFile -extensions v3_ca -out $SigningCACRT -infiles $SigningCACSR  -config $CaConfig"

        Write-host "Command to execute ["$openssl $arguments" ]" -foreground "green"


        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.RedirectStandardError = $true
        $processStartInfo.RedirectStandardOutput = $true
        $processStartInfo.UseShellExecute = $false
        $processStartInfo.FileName = $openssl
        $processStartInfo.Arguments = $arguments
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processStartInfo
        $process.Start() | Out-Null
        $process.WaitForExit()
        $standardError = $process.StandardError.ReadToEnd()
        if ($process.ExitCode) {
            Write-Error $standardError
        } else {
            Write-Host $standardError
        }

        if (Test-path $SigningCACRT){
            Write-host "Created signing crt file at ["$SigningCACRT"]" -foreground "cyan"
            return $SigningCACRT
        }
        Else {
            Write-host "ERROR: signing crt not created" -foregroundColor Red
            Exit        
        }
    }

	Else
	{
		Write-host "Couldn't find OpenSSL" -foreground "red"
        Exit
	}
}

#---------------------------------------------------------------------------------------------
#                     function Move-Signing-Files
#---------------------------------------------------------------------------------------------

function Move-Signing-Files([string]$rootFolder,[string]$CAPubFile,[string]$SigningCACRT){
    
    If($DebugPreference = "Continue") {Write-Debug "Move-Signing-Files $rootFolder" -ForegroundColor DarkGray}    
        
    $signingCA = Join-Path $rootFolder "SigningCA"
    
    $tempFile = Join-Path $signingCA "ca.db.index"
    New-Item $tempFile -ItemType file

    Move-Item "signing-ca*.*" $signingCA
    
    $random = Get-Random -Maximum 1000 -Minimum 1
    $tempFile = Join-Path $signingCA "ca.db.rand"
    New-Item $tempFile -ItemType file     
	$random | Out-File -FilePath $tempFile -Append

    $tempFile = Join-Path $signingCA "ca.db.serial"
    New-Item $tempFile -ItemType file     
	"01" | Out-File -FilePath $tempFile -Append

    ./RootCA = Join-Path $signingCA "ca.db.certs"
    New-Item -ItemType directory -path $signingCA

    $rootCAPEM = Join-Path $signingCA "root-ca.pem"
    
    Get-Content $CAPubFile, $SigningCACRT | Set-Content $rootCAPEM
}

#---------------------------------------------------------------------------------------------
#                     function Generate-CA-SigningFiles
#---------------------------------------------------------------------------------------------

function Generate-CA-SigningFiles([string]$rootFolder,[string]$CAPubFile){
    
    If($DebugPreference = "Continue") {Write-Debug "Generate-CA-SigningFiles $rootFolder $CAPubFile" -ForegroundColor DarkGray}

    $CASigningKey = Generate-Signing-Key $rootFolder
    
    Generate-Signing-Csr $rootFolder $CASigningKey  

    $SigningCACRT = Generate-Signing-Crt $rootFolder $CASigningKey  
    
    Move-Signing-Files $rootFolder $CAPubFile $SigningCACRT
}

#---------------------------------------------------------------------------------------------
#                     function Remove-Old-Nodes
#---------------------------------------------------------------------------------------------

function Remove-Old-Nodes([array]$nodes){
    
    If($DebugPreference = "Continue") {Write-Debug "Remove-Old-Nodes $nodes" -ForegroundColor DarkGray}

    Write-host 'Removing old Nodes...' -foreground "Cyan"
	Foreach($node in $nodes){
		$service = Get-WmiObject -Class Win32_Service -Filter "Name='$node'"
		if ($service){
			$service.delete()
			Write-host "Removed old node ["$node"]" -foreground "Cyan"
		}
	}
}

#---------------------------------------------------------------------------------------------
#                     function Remove-Old-Data
#---------------------------------------------------------------------------------------------

function Remove-Old-Data([array]$nodes){
    
    If($DebugPreference = "Continue") {Write-host "Remove-Old-Data $nodes" -ForegroundColor DarkGray}

    Write-host 'Removing old data folders...' -foreground "Cyan"
	Foreach ($node in $nodes){
		$path = Join-Path $rootFolder $node
		if (Test-Path $path){
		    Write-host "Removing old data from ["$path"]" -foreground "cyan"
			Get-ChildItem -Path $path -Include *.* -File -Recurse | foreach { $_.Delete()}
			Write-host "Removed content from folder ["$path"]" -foreground "Cyan"
		}
	}
}

#---------------------------------------------------------------------------------------------
#                     function Set-MongoDb-Config-File
#---------------------------------------------------------------------------------------------

function Set-MongoDb-Config-File([string]$rootFolder,[string]$node,[int]$currentPort){
    
    If($DebugPreference = "Continue") {Write-Debug "Set-MongoDb-Config-File $rootFolder $node $currentPort" -ForegroundColor DarkGray}

    Write-host 'Creating data folders...' -foreground "Cyan"
	$path = Join-Path $rootFolder $node
	$pathData = Join-Path $path "data"
	New-Item -ItemType directory -Path $pathData		
	Write-host "Created folder ["$pathData"]" -foreground "Cyan"
	$pathdb = Join-Path $pathData "db"
	New-Item -ItemType directory -Path $pathdb
	Write-host "Created folder ["$pathdb"]" -foreground "Cyan"
	$pathlogs = Join-Path $pathData "logs"
	New-Item -ItemType directory -Path $pathlogs
	Write-host "Created folder ["$pathlogs"]" -foreground "Cyan"
		
	Write-host "Creating Config file..." -foreground "Cyan"
		
	$configFile = Join-Path $path "mongod.cfg"
	New-Item $configFile -ItemType file
	"systemLog:" | Out-File -FilePath $configFile -Append
	"    destination: file" | Out-File -FilePath $configFile -Append
	$logdest = Join-Path $pathlogs "mongod.log"
	$temp = "    path: " + $logdest
	$temp | Out-File -FilePath $configFile -Append
	"storage:" | Out-File -FilePath $configFile -Append
	$temp = "    dbPath: " + $pathdb
	$temp | Out-File -FilePath $configFile -Append
	"replication:" | Out-File -FilePath $configFile -Append
	$temp = "    replSetName: " + $replicaSetName
	$temp | Out-File -FilePath $configFile -Append
	$temp = "    port: " + $ports[$currentPort]
	$temp | Out-File -FilePath $configFile -Append
	"    ssl:" | Out-File -FilePath $configFile -Append
	"        mode: allowSSL" | Out-File -FilePath $configFile -Append
	$temp = "        PEMKeyFile: " + $PEMKeyFile
	$temp | Out-File -FilePath $configFile -Append
	"processManagement:" | Out-File -FilePath $configFile -Append
	"    windowsService:" | Out-File -FilePath $configFile -Append
	$temp = "        serviceName: " + $node
	$temp | Out-File -FilePath $configFile -Append
	$temp = "        displayName: " + $node
	$temp | Out-File -FilePath $configFile -Append
	"security:" | Out-File -FilePath $configFile -Append
	"#    authorization: enabled" | Out-File -FilePath $configFile -Append
	$temp = "    keyFile: " + $filenameKeyFile
	$temp | Out-File -FilePath $configFile -Append
	
    if (Test-Path $configFile){
		Write-host "Created config file ["$configFile"]" -ForegroundColor Cyan
        return $configFile
    }
    Else{
        Write-host "ERROR: config file not created" -ForegroundColor Red
        Exit
    }
}

#---------------------------------------------------------------------------------------------
#                     function Register-Service
#---------------------------------------------------------------------------------------------

function Register-Service([string]$node,[string]$configFile){

    If($DebugPreference = "Continue") {Write-Debug "Register-Service $node $configFile" -ForegroundColor DarkGray}

    Write-host "Registering new service..." -foreground "Cyan"
		
	$mongo = "mongod.exe"		
		
	$arguments = "--config " + $configFile + "--install"
		
	Invoke-Process "$mongo $arguments"

	Write-host "Created Windows service ["$node"]" -foreground "Cyan"
		
	$net = "net"
	$arguments = "start " + $node
		
	Invoke-Process "$net $arguments"
}

#---------------------------------------------------------------------------------------------
#                     function Set-Windows-Services
#---------------------------------------------------------------------------------------------

function Set-Windows-Services([array]$nodes,[string]$rootFolder){
    
    If($DebugPreference = "Continue") {Write-Debug "Set-Windows-Services $nodes $rootFolder" -ForegroundColor DarkGray}

    $replicaSetName = Get-Value "ReplicaSet name" $defaultReplicaSetName

	$currentPort = 0
	Foreach ($node in $nodes){

        $configFile = Set-MongoDb-ConfigFile $rootFolder $node $currentPort
		
		Register-Service $node $configFile

		$currentPort++
		
	}
}
#---------------------------------------------------------------------------------------------
#
#                     B O D Y          =======================================================
#
#---------------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------------
#                     ROOT FOLDER
#---------------------------------------------------------------------------------------------

$rootFolder = Get-Value "Enter default root folder " $defaultRootFolder

#---------------------------------------------------------------------------------------------
#                     DOWNLOAD MONGODB INSTALLATION FILE
#---------------------------------------------------------------------------------------------

$downloadMongoDb = Get-Value "Download MongoDB Installation?" $defaultDownloadMongoDB

if ($downloadMongoDb -eq "Y"){
    Get-MongoDb  
}

#---------------------------------------------------------------------------------------------
#                     CREATE MONGODB KEYFILE
#---------------------------------------------------------------------------------------------

$createKeyFile = Get-Value "Create MongoDB KeyFile?" $defaultCreateKeyFile

if ($createKeyFile -eq "Y"){
    Set-MongoDb-KeyFile
}

#---------------------------------------------------------------------------------------------
#                     CREATE CA CERTIFICATES
#---------------------------------------------------------------------------------------------

$createCAFile = Get-Value "Create CA File?" $defaultCreateCA

if ($createCAFile -eq "Y"){

    $pub = Generate-CA-Files $rootFolder
    
    Generate-CA-SigningFiles $rootFolder $pub
}

#--------------------------------------------------------------------------------------------
#                        N O D E S
#--------------------------------------------------------------------------------------------
$numberOfNodes = Get-Value "Number of nodes in the ReplicaSet" $defaultNumberOfNodes

#--------------------------------------------------------------------------------------------
#                        W I N D O W S    S E R V I C E S
#--------------------------------------------------------------------------------------------
$servicePrefix = Get-Value "Service name prefix" $defaultServicePrefix

#--------------------------------------------------------------------------------------------
#                        P O R T S
#--------------------------------------------------------------------------------------------
$initialPort = Get-Value "Service initial Port" $defaultInitialPort

# Create and populate arrays
$nodes = @()
$ports = @()

for ($i=1; $i -le $numberOfNodes; $i++){
	$nodeName = $servicePrefix + "{0}" -f $i
	#$nodeName = $servicePrefix $i
	$nodes += $nodeName
	$ports += $initialPort + $i
}
Write-host "Nodes array ["$nodes"]" -foreground "cyan"

$removeInstances = Get-Value "Remove windows Services" $defaultRemoveInstances

if ($removeInstances -eq 'Y'){
    Remove-Old-Nodes $nodes
}

$removeOldData = Get-Value "Remove old data" $defaultRemoveOldData

if ($removeOldData -eq 'Y'){
    Remove--Old-Data $nodes
}

$createWindowsServices = Get-Value "Create new Windows Service" $defaultCreateWindowsServices

if ($createWindowsServices -eq 'Y'){

    Set-Windows-Services $nodes $rootFolder
}

$createRS = Get-Value "Create ReplicaSet?" $defaultCreateReplicaSet

if ($createRS -eq 'Y'){
	Write-host 'Creating replicaSet...'
	mongo --ssl --host mongo --port 27005 --shell initReplicaSet.js
} 

$createUsers = Get-Value "Create Users?" $defaultCreateUsers

if ($createUsers -eq 'Y'){
	Write-host 'Creating base Users...'
	mongo "mongodb://mongo:27005,mongo:27006,mongo:27007,mongo:27008/admin?replicaSet=TestRS" --ssl --shell initUsersAdmin.js
	mongo "mongodb://mongo:27005,mongo:27006,mongo:27007,mongo:27008/admin?replicaSet=TestRS" --ssl --shell initUsersRabbitMQ.js
}

Write-host 'Finished' -foreground "Cyan"
