##############################
#
# NOT FOR PRODUCTION USE
#
# REFERENCE CODE ONLY
#
# USE AT YOUR OWN RISK!!!!!!
#
##############################

$env:PATH += ";C:\Program Files (x86)\Yubico\YubiKey Manager"

$script:debug = $False

$runloop = $True


Function config_key {
    
    #Get serial number
    $ykInfo = invoke-expression "ykman.exe info" |
        select-string -pattern "Serial Number" |
            foreach-object { $_.tostring() } |
                foreach-object { $_.split(":") }

    $serialnumber = $ykInfo[1].trim()

    $config = get-content 'duo_build.json' | out-string | convertfrom-json

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
    
        $slot1publicid = $retdata | select-string -pattern "public ID" |
            foreach-object { $_.tostring() } |
                foreach-object { $_ -split "public ID:" }

        $slot1privateid = $retdata | select-string -pattern "private ID" |
            foreach-object { $_.tostring() } |
                foreach-object { $_ -split "private ID:" }

        $slot1secret = $retdata | select-string -pattern "secret key" |
            foreach-object { $_.tostring() } |
                foreach-object { $_ -split "secret key:" }

        $configpublicid = $slot1publicid[1].trim()
        $configprivateid = $slot1privateid[1].trim()
        $configsecretkey = $slot1secret[1].trim()
        
        # TODO: Need to export to DUO formatted file
        log-results $serialnumber $configprivateid $configsecretkey
        show-results "DUO information line $serialnumber,$configprivateid,$configsecretkey" "info"
    }
    
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
    if ($publicid -ne "serial"){$publicid = "-P '$publicid'"}else{$publicid = "-S"}
    if ($privateid -ne "random"){$privateid = "-p '$privateid'"}else{$privateid = "-g"}
    if ($secretkey -ne "random"){$secretkey = "-k '$secretkey'"}else{$secretkey = "-G"}

    $cmdrun = "$publicid $privateid $secretkey"

    show-results "OTP $slotid Run: $cmdrun" "info"
    $retdata = invoke-expression "ykman.exe otp yubiotp $slotid $cmdrun -f"
    return $retdata
}

Function Get-USB {
    $ykdev = gwmi win32_usbcontrollerdevice | %{[wmi]($_.Dependent)} | where {$_.name -eq "YubiKey Smart Card Minidriver"}

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

Function log-results($serialnumber, $configprivateid, $configsecretkey)
{

    $logmessage = "$serialnumber, $configprivateid, $configsecretkey"
    $logmessage | add-content "duo_import.csv"

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

write-host "**********************************************" -foregroundcolor red
write-host "**** USE AT YOUR OWN RISK               ******" -foregroundcolor red
write-host "**********************************************" -foregroundcolor red
write-host "This script will create a file with the configuration passwords"
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
