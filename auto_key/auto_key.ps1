

$script:defaultPIN = '123456'
$script:defaultPUK = '12345678'
$script:defaultMGT = '010203040506070801020304050607080102030405060708'
$script:keystatus = 'out'
$script:pinretries = 6
$script:pukretries = 6
$runloop = $True

Function config_key {
    
    #Get serial number
    $ykInfo = invoke-expression "ykman.exe info" |
        select-string -pattern "Serial Number" |
            foreach-object { $_.tostring() } |
                foreach-object { $_.split(":") }

    $serialnumber = $ykInfo[1].trim()

    $config = get-content 'auto_key.json' | out-string | convertfrom-json

    # Reset the key
    ykman.exe piv reset -f
    "Your YubiKey $serialnumber has been reset to factory configuration"
    
    if ($config.pinretries){
        $script:pinretries = $config.pinretries
    }

    if ($config.pukretries){
        $script:pukretries = $config.pukretries
    }

    # Set pin retries
    ykman.exe piv set-pin-retries -m $script:defaultMGT -P $script:defaultPIN $script:pinretries $script:pukretries -f
    "PIN and PUK retries have been updated"

    # Set PIN
    if ($config.defaultpin){
        switch($config.defaultpin){
            "serial" { $passPIN = $serialnumber }
            "random" { $passPIN = get-password 8 numeric}
            "factory" { $passPIN =  $script:defaultPIN}
            "static" {
                if ($config.staticpin){
                    $passPIN = $config.staticpin
                } else {
                    $passPIN = $script:defaultPIN
                }
            }
        }
    }

    if ($script:defaultPIN -ne $passPIN){
        ykman.exe piv change-pin -P $script:defaultPIN -n $passPIN
        write-host "New PIN: $passPIN" -foregroundcolor red
    }

    # Set PUK
    if ($config.defaultpuk){
        switch($config.defaultpuk){
            "serial" { $passPUK = $serialnumber }
            "random" { $passPUK = get-password 8 numeric}
            "factory" { $passPUK =  $script:defaultPUK}
            "static" {
                if ($config.staticpuk){
                    $passPUK = $config.staticpuk
                } else {
                    $passPUK = $script:defaultPUK
                }
            }
        }
    }

    if ($script:defaultPUK -ne $passPUK){
        ykman.exe piv change-puk -p $script:defaultPUK -n $passPUK
        write-host "New PUK: $passPUK" -foregroundcolor red
    }

    # Set MGT
    if ($config.defaultmgt){
        switch($config.defaultmgt){
            "random" { $passMGT = get-password 48 byte}
            "factory" { $passMGT =  $script:defaultMGT}
        }
    }

    if ($script:defaultMGT -ne $passMGT){
        ykman.exe piv change-management-key -m $script:defaultMGT -n $passMGT
        write-host "New Management Key: $passMGT" -foregroundcolor red
    }
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

Function get-password{
    Param(
        [parameter(Mandatory=$true)]
        [alias("l")]
        $len,

        [parameter(Mandatory=$false)]
        [alias("t")]
        $type
    )

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
