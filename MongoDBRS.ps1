#---------------------------------------------------------------------------------------------
#   Author:     Victor Zaragoza
#   Repository: https://github.com/victorxata/Powershell
#   Contact:    @victorxata
#   License:    Apache License Version 2.0 
#   Version:    1
#   Requires    -RunAsAdministrator
#---------------------------------------------------------------------------------------------

param([string]$debug="SilentlyContinue")

Write-host "Starting process" -foregroundColor Yellow
$DebugPreference = "Continue"
$installer = [MongoInstaller]::new()
$installer.DoProcess()
Write-host "Finished" -foregroundColor Yellow

#---------------------------------------------------------------------------------------------
#                      Utils  C L A S S
#---------------------------------------------------------------------------------------------

class Utils{

    InvokeProcess([string]$Exec, [string]$Arg) {

        If($DebugPreference = "Continue") {Write-Host "Invoke-Process $Exec $Arg" -ForegroundColor DarkGray}

        Write-host "Command to execute ["$Exec $Arg" ]" -foreground "green"

        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.RedirectStandardError = $true
        $processStartInfo.RedirectStandardOutput = $true
        $processStartInfo.UseShellExecute = $false

        $processStartInfo.FileName = $Exec
        $processStartInfo.Arguments = $Arg

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
     [string]$defaultOpenSSLBinFolder = "C:\oss\OpenSSL\bin"
     [string]$rootFolder
     [string]$openssl
     [string]$CAFile
     [string]$CAPubFile
     [string]$CACfgFile
     [string]$CASigningKey
     [string]$SigningCACSR
     [string]$SigningCACRT
     [string]$SigningCA
     [string]$rootCAPEM
     [string]$certsFolder
     [string]$opensslCfg
     [Utils]$Utils
     [string]$pemFile

    OpenSSLUtils([string]$root){
        $this.rootFolder = $root
        $this.Utils = [Utils]::new()
    }

    SetOpenSSLConfigFile(){

        If($DebugPreference = "Continue") {Write-host "OpenSSLUtils::SetOpenSSLConfigFile" -ForegroundColor DarkGray}

        $this.opensslCfg = Join-Path $this.opensslFolder "openssl.cfg"
        Write-host "Searching openssl config file at $this.opensslCfg" -ForegroundColor cyan

        if (-not (Test-Path $this.opensslCfg)){
            Write-host "Configuration not found, creating a new one" -ForegroundColor cyan
            New-Item $this.opensslCfg -ItemType file

   "                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             '        
HOME			= .
RANDFILE		= `$ENV::HOME/.rnd

oid_section		= new_oids




[ new_oids ]



tsa_policy1 = 1.2.3.4.1
tsa_policy2 = 1.2.3.4.5.6
tsa_policy3 = 1.2.3.4.5.7

[ ca ]
default_ca	= CA_default		# The default ca section


[ CA_default ]

dir		= ./demoCA		
certs		= `$dir/certs		
crl_dir		= `$dir/crl		
database	= `$dir/index.txt	
#unique_subject	= no			
					
new_certs_dir	= `$dir/newcerts		

certificate	= `$dir/cacert.pem 	
serial		= `$dir/serial 		
crlnumber	= `$dir/crlnumber	
					
crl		= `$dir/crl.pem 		
private_key	= `$dir/private/cakey.pem
RANDFILE	= `$dir/private/.rand	

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
nsComment			= 

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
nsComment			= 

authorityKeyIdentifier=keyid,issuer

proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo

[ tsa ]

default_tsa = tsa_config1	# the default TSA section

[ tsa_config1 ]

dir		= ./demoCA		
serial		= `$dir/tsaserial	
crypto_device	= builtin		
signer_cert	= `$dir/tsacert.pem 	
					
certs		= `$dir/cacert.pem	
					
signer_key	= `$dir/private/tsakey.pem 

default_policy	= tsa_policy1		
					
other_policies	= tsa_policy2, tsa_policy3	
digests		= md5, sha1		
accuracy	= secs:1, millisecs:500, microsecs:100	
clock_precision_digits  = 0	
ordering		= yes	
				
tsa_name		= yes	
				
ess_cert_id_chain	= no	
				

        " | Out-File -FilePath $this.opensslCfg -Append

            $env:OPENSSL_CONF = $this.opensslCfg
            $env:RANDFILE=".rnd"

            Write-Host "Set OPENSSL_CONF variable to $this.opensslCfg" -foregroundColor Green
        }
    }

    [string]OpenSSLCommand(){

        If($DebugPreference = "Continue") {Write-host "OpenSSLUtils::OpenSSLCommand" -ForegroundColor DarkGray}

        if($this.opensslFolder){
            if (-not(Test-Path $this.opensslFolder)){
                $this.opensslFolder = $this.Utils.GetValue("Input OpenSSL bin folder", $this.defaultOpenSSLBinFolder)
                $this.openssl = Join-Path $this.opensslFolder "openssl.exe"
            }
        } 
        Else {
            $this.opensslFolder = $this.Utils.GetValue("Input OpenSSL bin folder", $this.defaultOpenSSLBinFolder)
            $this.openssl = Join-Path $this.opensslFolder "openssl.exe"
        }
        return $this.openssl
    }
    
    GenerateRootCA(){
    
    If($DebugPreference = "Continue") {Write-Host "OpenSSLUtils::GenerateRootCA" -ForegroundColor DarkGray}

        $this.OpenSSLCommand()
        
        if (Test-path $this.openssl){

            $this.SetOpenSSLConfigFile()
        
            $this.CAFile = Join-Path $this.rootFolder "root-ca.key"

            $arguments = "genrsa -out " + $this.CAFile + " 2048"

           $this.Utils.InvokeProcess($this.openssl, $arguments)
                  
            if (Test-path $this.CAFile){
                Write-host "Created root-ca file at ["$this.CAFile"]" -foreground "cyan"
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

    GenerateRootCAcrt(){

        If($DebugPreference = "Continue") {Write-Host "OpenSSLUtils::GenerateRootCAcrt" -ForegroundColor DarkGray}

        $this.openssl = $this.OpenSSLCommand()
        
        if (Test-path $this.openssl){

            $this.CAPubFile = Join-Path $this.rootFolder "root-ca.crt"
        
            $subject = "/C=IE/ST=D/L=Accenture/O=Technology/CN=ROOTCA"
            $arg = "req -new -x509 -days 3650 -key " + $this.CAFile + " -out " + $this.CAPubFile + ' -subj "' + $subject + '"'
            $arguments = $arg
        
            $this.Utils.InvokeProcess($this.openssl, $arguments)
                  
            if (Test-path $this.CAPubFile){
                Write-host "Created CA public file at ["$this.CAPubFile"]" -foreground "cyan"
            }
            Else {
                Write-host "ERROR: CA public file not created" -foregroundColor Red
                Exit
            }
	    }
	    Else
	    {
		    Write-host "Couldn't find OpenSSL" -foreground "red"
            Exit
	    }
    }

    MoveCAFiles(){
    
        If($DebugPreference = "Continue") {Write-Host "OpenSSLUtils::MoveCAFiles" -ForegroundColor DarkGray}

        
        $rootCA = Join-Path $this.rootFolder "RootCA"
        Write-host "Creating folder "  $rootCA
        New-Item -ItemType directory -path $rootCA
        
        $tempFile = Join-Path $rootCA "ca.db.index"
        New-Item $tempFile -ItemType file

        Write-host "Moving files to " $rootCA
        $tempFile = Join-Path $this.rootFolder "root-ca.*"
        Move-Item $tempFile $rootCA

        $this.CAPubFile = Join-Path $rootCA "root-ca.crt"
        $this.CAFile = Join-Path $rootCA "root-ca.key"
    
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

        $this.CACfgFile = Join-Path $rootCA "root-ca.cfg"
        New-Item $this.CACfgFile -ItemType file

        $this.signingCA = Join-Path $this.rootFolder "SigningCA"
        New-Item -ItemType directory -path $this.signingCA
        
        $rootCA = $rootCA.Replace('\','\\')
        $this.SigningCA = $this.signingCA.Replace('\','\\')
        
        $temp1 = "
RANDFILE        = .rnd
[ ca ]
default_ca    = CA_default        # The default ca section

[ CA_default ]

dir           = C:\\openssl\\bin\\CA       # Where everything is kept
certs         = `$dir\\certs                # Where the issued certs are kept
crl_dir       = `$dir\\crl                  # Where the issued crl are kept
database      = `$dir\\index.txt            # database index file.
new_certs_dir = `$dir\\newcerts             # default place for new certs.

certificate   = `$dir\\cacert.pem           # The CA certificate
serial        = `$dir\\serial               # The current serial number
crl           = `$dir\\crl.pem              # The current CRL
private_key   = `$dir\\private\\cakey.pem   # The private key
RANDFILE      = `$dir\\private\\private.rnd # private random number file

x509_extensions  = x509v3_extensions        # The extentions to add to the cert
default_days     = 365                      # how long to certify for
default_crl_days = 30                       # how long before next CRL
default_md       = md5                      # which md to use.
preserve         = no                       # keep passed DN ordering

policy        = policy_match

[ policy_match ]
countryName            = match
stateOrProvinceName    = match
organizationName       = match
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ policy_anything ]
countryName            = Ireland
stateOrProvinceName    = Dublin
localityName           = Dublin
organizationName       = Vizasoft
organizationalUnitName = Technology
commonName             = supplied
emailAddress           = victorxata@gmail.com

[ req ]
default_bits        = 1024
default_keyfile     = privkey.pem
distinguished_name  = req_distinguished_name
attributes          = req_attributes

[ req_distinguished_name ]
countryName            = IE
countryName_min        = 2
countryName_max        = 2

stateOrProvinceName    = State or Province Name (full name)

localityName           = Locality Name (eg, city)

0.organizationName     = Organization Name (eg, company)

organizationalUnitName = Organizational Unit Name (eg, section)

commonName            = Common Name (eg, your website’s domain name)
commonName_max        = 64

emailAddress          = Email Address
emailAddress_max      = 40

[ req_attributes ]
challengePassword     = A challenge password
challengePassword_min = 4
challengePassword_max = 20

[ x509v3_extensions ]

[ RootCA ]
    dir             = " + $rootCA + " 
    certs           = `$dir\\ca.db.certs
    database        = `$dir\\ca.db.index
    new_certs_dir   = `$dir\\ca.db.certs
    certificate     = `$dir\\root-ca.crt
    serial          = `$dir\\ca.db.serial
    private_key     = `$dir\\root-ca.key
    RANDFILE        = `$dir\\ca.db.rand
    default_md      = sha256
    default_days    = 365
    default_crl_days= 30
    email_in_dn     = no
    unique_subject  = no
    policy          = policy_match

[ SigningCA ]
    dir             = " + $this.signingCA + "
    certs           = " + $this.signingCA + "\\ca.db.certs
    database        = " + $this.signingCA + "\\ca.db.index
    new_certs_dir   = " + $this.signingCA + "\\ca.db.certs
    certificate     = " + $this.signingCA + "\\signing-ca.crt
    serial          = " + $this.signingCA + "\\ca.db.serial
    private_key     = " + $this.signingCA + "\\signing-ca.key
    RANDFILE        = " + $this.signingCA + "\\ca.db.rand
    default_md      = sha256
    default_days    = 365
    default_crl_days= 30
    email_in_dn     = no
    unique_subject  = no
    policy          = policy_match

[ v3_ca ]
    subjectKeyIdentifier   = hash
    authorityKeyIdentifier = keyid:always,issuer
    basicConstraints       = CA:true

[ policy_match ]
    countryName            = match
    stateOrProvinceName    = match
    localityName           = match
    organizationName       = match
    organizationalUnitName = optional
    commonName             = supplied
    emailAddress           = optional

"

    $temp1 | Out-File -FilePath $this.CACfgFile -Append
    }

    GenerateCAFiles(){
    
    If($DebugPreference = "Continue") {Write-Host "OpenSSLUtils::GenerateCAFiles" -ForegroundColor DarkGray}

        $this.GenerateRootCA()

        $this.GenerateRootCAcrt()
    
        $this.MoveCAFiles()
    }

    GenerateSigningKey(){

        If($DebugPreference = "Continue") {Write-Host "OpenSSLUtils::GenerateSigningKey" -ForegroundColor DarkGray}

        $this.openssl = $this.OpenSSLCommand()
        
        if (Test-path $this.openssl){
        
            Write-host "Creating a signing key..."

            $this.CASigningKey = Join-Path $this.rootFolder "signing-ca.key"
            $arguments = "genrsa -out " + $this.CASigningKey + " 2048  "

             $this.Utils.InvokeProcess($this.openssl, $arguments)
                  
            if (Test-path $this.CASigningKey){
                Write-host "Created signing key file at ["$this.CASigningKey"]" -foreground "cyan"
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

    GenerateSigningCsr(){
    
        If($DebugPreference = "Continue") {Write-Host "OpenSSLUtils::GenerateSigningCsr" -ForegroundColor DarkGray}

        $this.openssl = $this.OpenSSLCommand()
        
        if (Test-path $this.openssl){

            $this.SigningCACSR = Join-Path $this.rootFolder "Signing-ca.csr"
            $subject = "/C=IE/ST=D/L=Accenture/O=Technology/CN=CA-SIGNER"
            $arg = "req -new -days 10000 -key " + $this.CASigningKey + " -out " + $this.SigningCACSR + ' -subj "' + $subject + '"' 
            $arguments = $arg

            $this.Utils.InvokeProcess($this.openssl, $arguments)
                  
            if (Test-path $this.SigningCACSR){
                Write-host "Created signing csr file at ["$this.SigningCACSR"]" -foreground "cyan"
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

    GenerateSigningCrt(){
    
        If($DebugPreference = "Continue") {Write-Host "OpenSSLUtils::GenerateSigningCrt" -ForegroundColor DarkGray}

        $this.openssl = $this.OpenSSLCommand()
        
        if (Test-path $this.openssl){
        
            #Invoke-Process $openssl $arguments

        
            $this.SigningCACRT = Join-Path $this.rootFolder "Signing-ca.crt"
            $arguments = "ca -batch -name RootCA -config " + $this.CACfgFile + " -extensions v3_ca -out " + $this.SigningCACRT + " -infiles " + $this.SigningCACSR

            $this.Utils.InvokeProcess($this.openssl, $arguments)

            if (Test-path $this.SigningCACRT){
                Write-host "Created signing crt file at ["$this.SigningCACRT"]" -foreground "cyan"
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

    MoveSigningFiles(){
    
        If($DebugPreference = "Continue") {Write-Host "OpenSSLUtils::MoveSigningFiles" -ForegroundColor DarkGray}    
        
        $tempFile = Join-Path $this.signingCA "ca.db.index"
        New-Item $tempFile -ItemType file

        $tempFile = Join-Path $this.rootCA "signing-ca.*"
        Move-Item $tempFile $this.signingCA
    
        $random = Get-Random -Maximum 1000 -Minimum 1
        $tempFile = Join-Path $this.signingCA "ca.db.rand"
        New-Item $tempFile -ItemType file     
	    $random | Out-File -FilePath $tempFile -Append

        $tempFile = Join-Path $this.signingCA "ca.db.serial"
        New-Item $tempFile -ItemType file     
	    "01" | Out-File -FilePath $tempFile -Append

        $this.certsFolder = Join-Path $this.signingCA "ca.db.certs"
        New-Item -ItemType directory -path $this.certsFolder

        $this.rootCAPEM = Join-Path $this.certsFolder "root-ca.pem"
    
        Get-Content $this.CAPubFile, $this.SigningCACRT | Set-Content $this.rootCAPEM
    }

    GenerateCASigningFiles(){
    
        If($DebugPreference = "Continue") {Write-Host "OpenSSLUtils::GenerateCASigningFiles" -ForegroundColor DarkGray}

        $this.GenerateSigningKey()
    
        $this.GenerateSigningCsr() 

        $this.GenerateSigningCrt()
    
        $this.MoveSigningFiles()
    }

    [string]GeneratePEMFile([string]$filename){

        If($DebugPreference = "Continue") {Write-Host "OpenSSLUtils::GeneratePEMFile" -ForegroundColor DarkGray}

        $this.openssl = $this.OpenSSLCommand()
        
        if (Test-path $this.openssl){
        
            #Invoke-Process $openssl $arguments

            $this.pemFile = $filename + ".pem"
            $this.pemFile = Join-Path $this.rootFolder $this.pemFile
            $crt = $filename + ".crt"
            $key = $filename + ".key"
            $crt = Join-Path $this.rootFolder $crt
            $key = Join-Path $this.rootFolder $key

            $subj = "/C=IE/ST=Dublin/L=Dublin/O=Vizasoft/OU=Technology/CN=mongodbTestRS"
            $arguments = "req -newkey rsa:2048 -new -x509 -days 365 -nodes -out " + $crt + " -keyout " + $key + ' -subj "' + $subj + '"' 

            $this.Utils.InvokeProcess($this.openssl, $arguments)

            
            
            cat $crt,$key | sc $this.pemFile 

            if (Test-path $this.pemFile){
                Write-host "Created PEM file at ["$this.pemFile"]" -foreground "cyan"
                return $this.pemFile
            }
            Else {
                Write-host "ERROR: PEM file not created" -foregroundColor Red
                Exit        
            }
        }

	    Else
	    {
		    Write-host "Couldn't find OpenSSL" -foreground "red"
            Exit
	    }
    }
}

#---------------------------------------------------------------------------------------------
#                      MongoDBUtils  C L A S S
#---------------------------------------------------------------------------------------------

class MongoDBUtils{
    
    [string]$defaultMongoDBMSIFileSource = "https://fastdl.mongodb.org/win32/mongodb-win32-x86_64-2008plus-ssl-3.4.2-signed.msi"
    [string]$defaultMongoDBMSIFileTarget = "mongodb.msi"
    [string]$defaultFileName = 'mongodb-keyfile.key'
    [string]$mongoDBTargetFolder = "C:\QueueSystem\Server"
    [string]$mongoDBAddLocal = '"ALL"'
    [string]$mongoDBMSIFileSource
    [string]$mongoDBMSIFileTarget
    [string]$filenameKeyFile
    [string]$rootFolder

    [OpenSSLUtils]$openSSLUtils
    [Utils]$Utils

    MongoDBUtils([Utils]$utl, [string]$root,[OpenSSLUtils]$openSSLUtl){
        $this.Utils = $utl
        $this.rootFolder = $root
        $this.openSSLUtils = $openSSLUtl
    }
    
    GetMongoDb(){

        If($DebugPreference = "Continue") {Write-Host "MongoDBUtils::GetMongoDb" -ForegroundColor DarkGray}

        $this.mongoDBMSIFileSource = $this.Utils.GetValue("Enter source msi file", $this.defaultMongoDBMSIFileSource)

        $this.mongoDBMSIFileTarget = $this.Utils.GetValue("Enter target msi file name", $this.defaultMongoDBMSIFileTarget)

        if (-Not (Test-Path $this.mongoDBMSIFileTarget)){
            Write-host "Downloading MongoDB installation MSI File..." -foreground "green"
            curl -o $this.mongoDBMSIFileTarget $this.mongoDBMSIFileSource
        }

        <#
        Write-host "Create MongoDB Server Folder $this.mongoDBTargetFolder" -foreground "green"
        New-Item -ItemType directory -path $this.mongoDBTargetFolder
        #>
        
        $this.mongoDBTargetFolder = '"' + $this.mongoDBTargetFolder + '"'

        $arguments = "/quiet /passive /i $this.mongoDBMSIFileTarget INSTALLLOCATION=$this.mongoDBTargetFolder ADDLOCAL=$this.mongoDBAddLocal"

        $arg = '/quiet /passive /i ' 
        $arg = $arg + $this.mongoDBMSIFileTarget
        $arg = $arg + " INSTALLLOCATION=" 
        $arg = $arg + $this.mongoDBTargetFolder 
        $arg = $arg + " ADDLOCAL=" 
        $arg = $arg + $this.mongoDBAddLocal
        
        If($DebugPreference = "Continue") {Write-Host "MongoDBUtils::GetMongoDb::Args $args" -ForegroundColor DarkGray}
        $this.Utils.InvokeProcess("msiexec.exe", $arg)

        Write-host "MongoDB installed" -ForegroundColor "cyan"
    }

    [string]SetMongoDbKeyFile(){

        If($DebugPreference = "Continue") {Write-Host "Set-MongoDb-KeyFile" -ForegroundColor DarkGray}

        $this.filenameKeyFile = $this.Utils.GetValue("Input MongoDB KeyFile", $this.defaultFileName)

	    $this.filenameKeyFile = Join-Path $this.rootFolder $this.filenameKeyFile

	    Write-host "Selected Keyfile ["$this.filenameKeyFile" ]" -foreground "green" 
	
	    $openssl = $this.openSSLUtils.OpenSSLCommand()
    
	    $arguments = "rand -base64 756 -out " + $this.filenameKeyFile
	
	    if (Test-path $openssl){

            $this.Utils.InvokeProcess($openssl, $arguments)
        
            if (Test-path $this.filenameKeyFile){
                Write-host "Created KeyFile at ["$this.filenameKeyFile"]" -foreground "cyan"
                return $this.filenameKeyFile
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

}

#---------------------------------------------------------------------------------------------
#                      Nodes  C L A S S
#---------------------------------------------------------------------------------------------

class Nodes{

    [string]$rootFolder
    [string]$defaultServicePrefix = 'mongodbX'
    [string]$defaultInitialPort = 27100
    [string]$defaultNumberOfNodes = 4
    [array]$nodes
    [array]$ports
    [string]$defaultReplicaSetName = 'TestRS'
    [string]$replicaSetName
    [Utils]$Utils
    [string]$keyFile
    [string]$pemFile

    Nodes([string]$root,[Utils]$utl,[string]$key,[string]$pem){
        $this.rootFolder = $root
        $this.Utils = $utl
        $this.keyFile = $key
        $this.pemFile = $pem

        $numberOfNodes = $this.Utils.GetValue("Number of nodes in the ReplicaSet", $this.defaultNumberOfNodes)

        $servicePrefix = $this.Utils.GetValue("Service name prefix", $this.defaultServicePrefix)

        $initialPort = $this.Utils.GetValue( "Service initial Port", $this.defaultInitialPort)

        $this.nodes = @()
        $this.ports = @()

        for ($i=1; $i -le $numberOfNodes; $i++){
	        $nodeName = $servicePrefix + "{0}" -f $i
	        $this.nodes += $nodeName
	        $this.ports += [int]$initialPort + [int]$i
        }
        Write-host "Nodes array ["$this.nodes"]" -foreground "cyan"
        Write-host "Ports array ["$this.ports"]" -foreground "cyan"
    }

    RemoveNodes(){
    
        If($DebugPreference = "Continue") {Write-Host "Nodes::RemoveOldNodes" -ForegroundColor DarkGray}

        Write-host 'Removing Nodes...' -foreground "Cyan"
	    Foreach($node in $this.nodes){
        $net = "mongod"
	    $arguments = "--serviceName " + $node + " --remove"

        $this.Utils.InvokeProcess($net, $arguments)
		
        <#    $service = Get-WmiObject -Class Win32_Service -Filter "Name='$node'"
		    if ($service){
			    $service.delete()
                if (-not ($service)){
			        Write-host "Removed Node ["$node"]" -foreground "Cyan"
		        }
            }#>
	    }
    }

    RemoveData(){
    
        If($DebugPreference = "Continue") {Write-host "Nodes::RemoveData" -ForegroundColor DarkGray}

        Write-host 'Removing old data folders...' -foreground "Cyan"
	    Foreach ($node in $this.nodes){
		    $path = Join-Path $this.rootFolder $node
		    if (Test-Path $path){
		        Write-host "Removing old data from ["$path"]" -foreground "cyan"
			    Get-ChildItem -Path $path -Include *.* -File -Recurse | foreach { $_.Delete()}
			    Write-host "Removed content from folder ["$path"]" -foreground "Cyan"
		    }
	    }
    }

    [string]CreateMongoDBConfigFile([string]$node, [int]$port){
        
        If($DebugPreference = "Continue") {Write-Host "Nodes::CreateMongoDBConfigFile" -ForegroundColor DarkGray}

        Write-host 'Creating data folders...' -foreground "Cyan"
	    $path = Join-Path $this.rootFolder $node
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
	    $temp = "    replSetName: " + $this.replicaSetName
	    $temp | Out-File -FilePath $configFile -Append
	            "net:" | Out-File -FilePath $configFile -Append
	    $temp = "    port: " + $port
	    $temp | Out-File -FilePath $configFile -Append
	            "    ssl:" | Out-File -FilePath $configFile -Append
	            "        mode: allowSSL" | Out-File -FilePath $configFile -Append
	    $temp = "        PEMKeyFile: " + $this.PemFile
	    $temp | Out-File -FilePath $configFile -Append
	            "processManagement:" | Out-File -FilePath $configFile -Append
	            "    windowsService:" | Out-File -FilePath $configFile -Append
	    $temp = "        serviceName: " + $node
	    $temp | Out-File -FilePath $configFile -Append
	    $temp = "        displayName: " + $node
	    $temp | Out-File -FilePath $configFile -Append
	            "security:" | Out-File -FilePath $configFile -Append
	            "#    authorization: enabled" | Out-File -FilePath $configFile -Append
	    $temp = "    keyFile: " + $this.keyFile
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

    RegisterService([string]$node,[string]$configFile){

        If($DebugPreference = "Continue") {Write-Host "Nodes::RegisterService $node $configFile" -ForegroundColor DarkGray}

        Write-host "Registering new service..." -foreground "Cyan"
		
	    $mongo = "mongod.exe"		
		
	    $arguments = "--config " + $configFile + " --install"
		
	    $this.Utils.InvokeProcess($mongo, $arguments)

	    Write-host "Created Windows service ["$node"]" -foreground "Cyan"
		
	    $net = "net"
	    $arguments = "start " + $node
		
	    $this.Utils.InvokeProcess($net, $arguments)
    }

    SetWindowsServices(){
    
    If($DebugPreference = "Continue") {Write-Host "Nodes::SetWindowsServices" -ForegroundColor DarkGray}

        $this.replicaSetName = $this.Utils.GetValue("ReplicaSet name", $this.defaultReplicaSetName)

	    $currentPort = 0
	    Foreach ($node in $this.nodes){

            $configFile = $this.CreateMongoDBConfigFile($node, $this.ports[$currentPort])
		
		    $this.RegisterService($node, $configFile)

		    $currentPort++
	    }
    }

    CreateReplicaSet(){
    
        $replicaSetJS = '
rs.initiate( 
   { _id:"' + $this.replicaSetName + '"' + ",`r`n
      members:[        `r`n"
        [int]$port = 0
        Foreach($node in $this.nodes){
            $hostRS = '"localhost:' + $this.ports[$port]  + '"' 
            $replicaSetJS = $replicaSetJS + '{ _id:' + $port + ',host:' + $hostRS + '},' 
            $port ++
	    }
        $replicaSetJS = $replicaSetJS.Substring(0,$replicaSetJS.Length-1)
        $replicaSetJS = $replicaSetJS + "`r`n]
   }
);
conf=rs.conf();`r`n"

        $port = 0
        Foreach($node in $this.nodes){
            $replicaSetJS = $replicaSetJS + "conf.members[" + $port + "].priority=1;`r`n"
            $port++
        }
        $replicaSetJS = $replicaSetJS + "rs.reconfig(conf);
  rs.slaveOk();
  quit();"

        $replicaSetJSFile = Join-Path $this.rootFolder "initReplicaSet.js"
        if (Test-Path $replicaSetJSFile){
            Remove-Item $replicaSetJSFile
        }
        $replicaSetJS | Out-File $replicaSetJSFile

        $exec = "mongo"
        $arguments = "--port "+ $this.ports[0] + " admin --shell " + $replicaSetJSFile
        $this.Utils.InvokeProcess($exec, $arguments)

    }

    CreateReplicaSetUsers(){
        
        mongo "mongodb://mongo:27005,mongo:27006,mongo:27007,mongo:27008/admin?replicaSet=TestRS" --ssl --shell initUsersAdmin.js
	    mongo "mongodb://mongo:27005,mongo:27006,mongo:27007,mongo:27008/admin?replicaSet=TestRS" --ssl --shell initUsersRabbitMQ.js
    
    }
}

#---------------------------------------------------------------------------------------------
#                      MongoInstaller  C L A S S
#---------------------------------------------------------------------------------------------


class MongoInstaller{
    #---------------------------------------------------------------------------------------------
    #                       D E F A U L T    V A L U E S
    #---------------------------------------------------------------------------------------------

    [string]$defaultDownloadMongoDB       = 'N'
    [string]$defaultCreateKeyFile         = 'Y'
    [string]$defaultRemoveInstances       = 'Y'
    [string]$defaultRemoveOldData         = 'Y'
    [string]$defaultCreateWindowsServices = 'Y'
    [string]$defaultCreateReplicaSet      = 'Y'
    [string]$defaultCreateUsers           = 'Y'
    [string]$defaultCreatePEM             = 'Y'
    [string]$defaultRootFolder            = 'C:\QueueSystem'
    [string]$rootFolder
    [string]$defaultCreateCA              = 'Y'
    [string]$defaultCreateCert            = 'Y'
    [string]$defaultCertFile              = "mongoRS"
    [string]$ou_member                    = "MyServers"
    [string]$ou_client                    = "MyClients"
    [string]$pemFile
    [string]$defaultPEMFile   
    [string]$defaultMongoDbKeyFile        = 'c:\QueueSystem\mongodb-keyfile.key'
    [string]$keyFile            

    [Utils]$Utils 

    [Nodes]$Nodes
    
    [MongoDBUtils]$MongoDB

    [OpenSSLUtils]$OpenSSL 

    MongoInstaller(){

        $this.Utils = [Utils]::new()

    }

    DoProcess(){

        $this.rootFolder = $this.Utils.GetValue("Enter default root folder ", $this.defaultRootFolder)

        $downloadMongoDb = $this.Utils.GetValue("Install MongoDB?", $this.defaultDownloadMongoDB)
                
        $this.OpenSSL = [OpenSSLUtils]::new($this.rootFolder)

        $this.MongoDB = [MongoDBUtils]::new($this.Utils, $this.rootFolder,[OpenSSLUtils]$this.OpenSSL)
        
        if ($downloadMongoDb -eq "Y"){
            $this.MongoDB.GetMongoDb()  
        }

        $createCAFile = $this.Utils.GetValue("Create CA File?", $this.defaultCreateCA)

        if ($createCAFile -eq "Y"){

            $this.OpenSSL.GenerateCAFiles()
    
            $this.OpenSSL.GenerateCASigningFiles()
        }

        $createMongoKeyFile = $this.Utils.GetValue("Create MongoDB KeyFile?", $this.defaultCreateKeyFile)

        if ($createMongoKeyFile -eq "Y"){
            $this.keyFile = $this.MongoDB.SetMongoDbKeyFile()
        }
        Else{
            if(-not($this.defaultMongoDBKeyFile)){
                Write-Host "Error: A keyFile is needed" -ForegroundColor Red
                Exit
            }
            $this.keyFile = $this.defaultMongoDBKeyFile
        }
        
        $createPEMFile = $this.Utils.GetValue("Create a new PEM file?", $this.defaultCreatePEM)

        if ($createPEMFile -eq "Y"){
            $this.pemFile = $this.OpenSSL.GeneratePEMFile($this.defaultCertFile)
        }

        if (-not ($this.pemFile)){
            $this.defaultPEMFile = Join-Path $this.rootFolder $this.defaultCertFile
            $this.defaultPEMFile = $this.defaultPEMFile + ".pem"
            $this.pemFile = $this.Utils.GetValue("Enter existing PEM file: ", $this.defaultPEMFile)
        }

        if (-not (Test-Path $this.pemFile)){
            Write-Host "Error: A certificate is needed" -ForegroundColor Red
            Exit
        }

        $this.Nodes = [Nodes]::new($this.rootFolder, $this.Utils, $this.keyFile, $this.pemFile)

        $removeInstances = $this.Utils.GetValue("Remove windows Services", $this.defaultRemoveInstances)

        if ($removeInstances -eq "Y"){
            $this.Nodes.RemoveNodes()
        }

        $removeOldData = $this.Utils.GetValue("Remove old data", $this.defaultRemoveOldData)

        if ($removeOldData -eq 'Y'){
            $this.Nodes.RemoveData()
        }

        $createWindowsServices = $this.Utils.GetValue("Create new Windows Service", $this.defaultCreateWindowsServices)

        if ($createWindowsServices -eq 'Y'){

            $this.Nodes.SetWindowsServices()
        }

        $createReplicaSet = $this.Utils.GetValue("Create ReplicaSet?", $this.defaultCreateReplicaSet)

        if ($createReplicaSet -eq 'Y'){
            $this.Nodes.CreateReplicaSet()
        }

        $createUsers = $this.Utils.GetValue("Create Users?", $this.defaultCreateUsers)

        if ($createUsers -eq 'Y'){
            $this.Nodes.CreateReplicaSetUsers()
        }
    }

}




