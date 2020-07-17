[string]$api_uri = "https://api.console.dev.in.yubico.org/v1/products"
[string]$content_type = "application/json"
[string]$method = "GET"

$headers=@{
    "Authorization" = "Bearer "
}

$ws = new-object Microsoft.PowerShell.Commands.WebRequestSession

# Only required for SE Demo URL
# IIAP AUTH TOKEN
$cookie = New-Object System.Net.Cookie
$cookie.Name = "GCP_IAAP_AUTH_TOKEN_9C3013A3C4153CC4"
$cookie.Value = ""
$cookie.Domain = "api.console.dev.in.yubico.org"
$ws.Cookies.Add($cookie)

$cookie = New-Object System.Net.Cookie
$cookie.Name = "GCP_IAP_UID"
$cookie.Value = ""
$cookie.Domain = "api.console.dev.in.yubico.org"
$ws.Cookies.Add($cookie)
# END of SE Demo Section


$props = @{
    Uri = $api_uri
    Headers = $headers
    ContentType = $content_type
    Method = $method
    WebSession = $ws
}

$resp = Invoke-RestMethod @props

if($resp)
{
    Return $resp
}
else {
    Return $False
}
