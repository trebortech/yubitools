param(
    [string]$sn = ""
    )

$env:PATH = "C:\Program Files (x86)\Yubico\YubiKey Manager"

$script:defaultPIN = '123456'
$script:defaultPUK = '12345678'
$script:defaultMGT = '010203040506070801020304050607080102030405060708'
$script:keystatus = 'out'
$script:pinretries = 6
$script:pukretries = 6
$script:debug = $False
$script:passphrase = ''
$script:salt = 'vvculgkkgjjeicilljrrigrnbfjlb'
$script:init = 'dvcdjfigdjuuihnedkfhfbltbirrjvjcvnd'
$runloop = $True

function get-keyinfo([int]$getserialnumber){

    $ykobj = @{}
    $logfile = get-content 'auto_key_results.csv' -raw 
    $lines = $logfile -split "\n"

    foreach($line in $lines){
        $lineobj = $line -split "\|"
        $serialnumber = [int]$lineobj[0]
        if ($serialnumber){
            if ($ykobj[$serialnumber]){
                write-host "Found it"
            }
            else
            {
                $linearr = @{
                    logdate = $lineobj[1]
                    pivsecuredata = $lineobj[2]
                }
                $ykobj[$serialnumber] = $linearr
            }
        }
    }

    return $ykobj.item($getserialnumber)
}



Function config_key {
    
    #Get serial number
    $ykInfo = invoke-expression "ykman.exe info" |
        select-string -pattern "Serial Number" |
            foreach-object { $_.tostring() } |
                foreach-object { $_.split(":") }

    $serialnumber = $ykInfo[1].trim()

    $config = get-content 'auto_key.json' | out-string | convertfrom-json

    if ($config.debug){
        $script:debug = $config.debug
    }

    #*********************** MODE Configuration ************************
    if ($config.mode) {
        ykman.exe mode $config.mode -f
    }


    #***********************  Slot Configuration ************************

    #SLOT 1
    if ($config.slot1){
        $slot1 = $config.slot1
        
        if ($slot1.type -eq "otp"){
            $retdata = Set-OTP 1 $slot1.publicid $slot1.privateid $slot1.secretkey
        }
    

        $slot1data = $retdata | select-string -pattern "secret key" |
            foreach-object { $_.tostring() } |
                foreach-object { $_ -split "secret key:" }

        $configsecretkey = $slot1data[1].trim()
        show-results "The secret key assigned: $configsecretkey" "info"
    }
    
    #SLOT 2
    if ($config.slot2){
        $slot2 = $config.slot2

        if ($slot2.type -eq "otp"){
            $retdata2 = Set-OTP 2 $slot2.publicid $slot2.privateid $slot2.secretkey
        }
    
        $slot2data = $retdata2 | select-string -pattern "secret key" |
            foreach-object { $_.tostring() } |
                foreach-object { $_ -split "secret key:" }

        $configsecretkey2 = $slot2data[1].trim()
        show-results "The secret key assigned: $configsecretkey2" "info"
    }

    
    #***********************  OPENPGP Configuration ************************

    if ($config.openpgp){
        $pgp = $config.openpgp
    }


    #***********************  OATH Configuration ************************

    #if ($config.oath){
    #    $oaths = $config.oath

    #    for ($oath in $oaths){

    #        $type = $oath.type
    #        }
    #}

    # Sleep necessary for smooth transition into PIV config
    start-sleep -s 3
    #***********************  PIV Configuration ************************
    # Reset the key
    ykman.exe piv reset -f
    "Your YubiKey $serialnumber has been reset to factory configuration"
    
    $ccid = $config.ccid

    if ($ccid.pinretries){
        $script:pinretries = $ccid.pinretries
    }

    if ($ccid.pukretries){
        $script:pukretries = $ccid.pukretries
    }

    # Set pin retries
    ykman.exe piv set-pin-retries -m $script:defaultMGT -P $script:defaultPIN $script:pinretries $script:pukretries -f
    "PIN and PUK retries have been updated"

    # Set PIN
    if ($ccid.defaultpin){
        switch($ccid.defaultpin){
            "serial" { $passPIN = $serialnumber }
            "random" { $passPIN = get-password 8 numeric}
            "factory" { $passPIN =  $script:defaultPIN}
            "static" {
                if ($ccid.staticpin){
                    $passPIN = $ccid.staticpin
                } else {
                    $passPIN = $script:defaultPIN
                }
            }
        }
    }

    if ($script:defaultPIN -ne $passPIN){
        ykman.exe piv change-pin -P $script:defaultPIN -n $passPIN
        show-results "New PIN: $passPIN" "info"
    }

    # Set PUK
    if ($ccid.defaultpuk){
        switch($ccid.defaultpuk){
            "serial" { $passPUK = $serialnumber }
            "random" { $passPUK = get-password 8 numeric}
            "factory" { $passPUK =  $script:defaultPUK}
            "static" {
                if ($ccid.staticpuk){
                    $passPUK = $ccid.staticpuk
                } else {
                    $passPUK = $script:defaultPUK
                }
            }
        }
    }

    if ($script:defaultPUK -ne $passPUK){
        ykman.exe piv change-puk -p $script:defaultPUK -n $passPUK
        show-results "New PUK: $passPUK" "info"
    }

    # Set MGT
    if ($ccid.defaultmgt){
        switch($ccid.defaultmgt){
            "random" { $passMGT = get-password 48 byte}
            "factory" { $passMGT =  $script:defaultMGT}
        }
    }

    if ($script:defaultMGT -ne $passMGT){
        ykman.exe piv change-management-key -m $script:defaultMGT -n $passMGT
        show-results "New Management Key: $passMGT" "info"
    }

    $senstivedata = "$passPIN | $passPUK | $passMGT"
    $cleardata = "$script:pinretries | $script:pukretries"
    log-results $serialnumber $senstivedata $cleardata
}


Function show-results($message, $type){
    if ($script:debug -eq "True"){
        switch ($type)
            {
                "error" {write-host $message -foregroundcolor red}
                "info" {write-host $message -foregroundcolor green}
                "warning" {write-host $message -foregroundcolor yellow}
            }
        }
    }

Function Set-OTP($slotid, $publicid, $privateid, $secretkey)
{
    if ($publicid -ne "serial"){$publicid = "-P '$publicid'"}else{$publicid = ""}
    if ($privateid -ne "random"){$privateid = "-p '$privateid'"}else{$privateid = ""}
    if ($secretkey -ne "random"){$secretkey = "-k '$secretkey'"}else{$secretkey = ""}

    $cmdrun = "$publicid $privateid $secretkey"

    show-results "OTP $slotid Run: $cmdrun" "info"
    $retdata = invoke-expression "ykman.exe slot otp $slotid $cmdrun -f"
    return $retdata
}

Function Get-USB {
    $ykdev = gwmi win32_usbcontrollerdevice | %{[wmi]($_.Dependent)} | where {$_.name -eq "YubiKey Smart Card"}

    if (!$ykdev){
        $script:keystatus = 'out'
        'No YubiKey connected'
    } elseif ($ykdev.gettype().name -eq 'ManagementObject' -AND $keystatus -eq 'out'){
        $script:keystatus = 'in'
        config_key
    } elseif ($ykdev.gettype().name -eq 'ManagementObject' -AND $keystatus -eq 'in'){
        'Please remove key'
    } elseif ($ykdev.gettype().name -eq 'Object[]'){
        $script:keystatus = 'in'
        'Too many YubiKeys connected.'
    } else {
        $ykdev.gettype().name
        'No good match'
    }
}

function log-results($serialnumber, $pivsecuredata, $pivcleardata, $otpsecuredata="", $otpcleardata="")
{
    # Need to encrypt pivsecuredata
    $pivsecuredata = Encrypt-String $pivsecuredata $script:passphrase
    # Need to encrypt otpsecuredata

    $otpsecuredata = Encrypt-String $pivsecuredata $script:passphrase
    
    $logdate = get-date
    $logdate = $logdate.tostring()

    $logmessage = "$serialnumber | $logdate | $pivsecuredata | $pivcleardata | $otpsecuredata | $otpcleardata"
    $logmessage | add-content "auto_key_results.csv"

}

Function get-password($len, $type=''){

    switch ($type)
    {
        "alphanumeric" { $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()_" }
        "numeric" { $chars = "1234567890" }
        "byte" { $chars = "1234567890abcdef" }
        default { $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()_" }
    }

    $bytes = new-object "System.Byte[]" $len
    $rnd = new-object System.Security.Cryptography.RNGCryptoServiceProvider
    $rnd.GetBytes($bytes)

    $result = ""
    for( $i=0; $i -lt $len; $i++ ){
        $result += $chars[ $bytes[$i] % $chars.Length]
    }

    return $result    
}

function Encrypt-String($String, $Passphrase, $salt=$script:salt, $init=$script:init, [switch]$arrayOutput) 
{ 
    # Create a COM Object for RijndaelManaged Cryptography 
    $r = new-Object System.Security.Cryptography.RijndaelManaged 
    # Convert the Passphrase to UTF8 Bytes 
    $pass = [Text.Encoding]::UTF8.GetBytes($Passphrase) 
    # Convert the Salt to UTF Bytes 
    $salt = [Text.Encoding]::UTF8.GetBytes($salt) 
 
    # Create the Encryption Key using the passphrase, salt and SHA1 algorithm at 256 bits 
    $r.Key = (new-Object Security.Cryptography.PasswordDeriveBytes $pass, $salt, "SHA1", 5).GetBytes(32) #256/8 
    # Create the Intersecting Vector Cryptology Hash with the init 
    $r.IV = (new-Object Security.Cryptography.SHA1Managed).ComputeHash( [Text.Encoding]::UTF8.GetBytes($init) )[0..15] 
     
    # Starts the New Encryption using the Key and IV    
    $c = $r.CreateEncryptor() 
    # Creates a MemoryStream to do the encryption in 
    $ms = new-Object IO.MemoryStream 
    # Creates the new Cryptology Stream --> Outputs to $MS or Memory Stream 
    $cs = new-Object Security.Cryptography.CryptoStream $ms,$c,"Write" 
    # Starts the new Cryptology Stream 
    $sw = new-Object IO.StreamWriter $cs 
    # Writes the string in the Cryptology Stream 
    $sw.Write($String) 
    # Stops the stream writer 
    $sw.Close() 
    # Stops the Cryptology Stream 
    $cs.Close() 
    # Stops writing to Memory 
    $ms.Close() 
    # Clears the IV and HASH from memory to prevent memory read attacks 
    $r.Clear() 
    # Takes the MemoryStream and puts it to an array 
    [byte[]]$result = $ms.ToArray() 
    # Converts the array from Base 64 to a string and returns 
    return [Convert]::ToBase64String($result) 
} 

function Decrypt-String($Encrypted, $Passphrase, $salt=$script:salt, $init=$script:init) 
{ 
    # If the value in the Encrypted is a string, convert it to Base64 
    if($Encrypted -is [string]){ 
        $Encrypted = [Convert]::FromBase64String($Encrypted) 
       } 
 
    # Create a COM Object for RijndaelManaged Cryptography 
    $r = new-Object System.Security.Cryptography.RijndaelManaged 
    # Convert the Passphrase to UTF8 Bytes 
    $pass = [Text.Encoding]::UTF8.GetBytes($Passphrase) 
    # Convert the Salt to UTF Bytes 
    $salt = [Text.Encoding]::UTF8.GetBytes($salt) 
 
    # Create the Encryption Key using the passphrase, salt and SHA1 algorithm at 256 bits 
    $r.Key = (new-Object Security.Cryptography.PasswordDeriveBytes $pass, $salt, "SHA1", 5).GetBytes(32) #256/8 
    # Create the Intersecting Vector Cryptology Hash with the init 
    $r.IV = (new-Object Security.Cryptography.SHA1Managed).ComputeHash( [Text.Encoding]::UTF8.GetBytes($init) )[0..15] 
 
 
    # Create a new Decryptor 
    $d = $r.CreateDecryptor() 
    # Create a New memory stream with the encrypted value. 
    $ms = new-Object IO.MemoryStream @(,$Encrypted) 
    # Read the new memory stream and read it in the cryptology stream 
    $cs = new-Object Security.Cryptography.CryptoStream $ms,$d,"Read" 
    # Read the new decrypted stream 
    $sr = new-Object IO.StreamReader $cs 
    # Return from the function the stream 
    Write-Output $sr.ReadToEnd() 
    # Stops the stream     
    $sr.Close() 
    # Stops the crypology stream 
    $cs.Close() 
    # Stops the memory stream 
    $ms.Close() 
    # Clears the RijndaelManaged Cryptology IV and Key 
    $r.Clear() 
} 


if($sn){
    write-host "Serial Number supplied"
    # getpassword for file
    write-host "Password to decrypt file:"
    $script:passphrase = read-host

    # get serial number line
    $keyobj = get-keyinfo $sn

    write-host $keyobj.pivsecuredata.trim()

    #decrypt
    $pivdata = Decrypt-String $keyobj.pivsecuredata $script:passphrase
    write-host $pivdata
    exit
}


# Check to see if ykman is installed and working
try{
    $ykInfo = invoke-expression "ykman.exe -v"
    }
catch{
    write-host "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
    write-host " "
    write-host "You must first install the YubiKey Manager QT for Windows"
    write-host "More information can be found at https://developers.yubico.com/yubikey-manager-qt/"
    write-host " "
    write-host "Download installer at https://developers.yubico.com/yubikey-manager-qt/Releases/"
    write-host " "
    write-host "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
    break
}

write-host "**********************************************"
write-host "This script will create a file with the "
write-host "configuration passwords encrypted"
write-host "Please enter the password that you would"
write-host "like to use to encrypt this file."
write-host "*** NOTE: This password will NOT be recorded anywhere"
write-host "*** If you forget it or misplace it you will not be able"
write-host "*** to decrypt the exported file"
$script:passphrase = read-host
if ($script:passphrase.length -lt 10){

    write-host "Password must be atleast 10 characters long"
    write-host "Please start over"
    exit
}
write-host "*************  WARNING  **********************" -foregroundcolor red
write-host "This will reset the Yubikey that is currently connected."
write-host "Do you want to continue?"
write-host "y / N"
$response = read-host
if ($response -ne "y") {exit}
write-host "**********************************************" -foregroundcolor yellow
write-host "***"  -foregroundcolor yellow
write-host "***       Exit with `"q`""  -foregroundcolor yellow
write-host "***"  -foregroundcolor yellow
write-host "**********************************************" -foregroundcolor yellow

while ($runloop) {
    if ([console]::KeyAvailable){
        $x = [system.console]::readkey()
        if ($x.key -eq 'q'){
            $runloop = $False
        }
    }
    get-usb
    start-sleep -s 3
}
