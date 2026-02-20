$adminSecret = "change-me-immediately"
$baseUrl = "http://localhost:5000"

function Test-Endpoint {
    param($method, $uri, $body=$null)
    $headers = @{ "Admin-Secret" = $adminSecret; "Content-Type" = "application/json" }
    try {
        if ($body) {
            $response = Invoke-RestMethod -Method $method -Uri "$baseUrl$uri" -Headers $headers -Body ($body | ConvertTo-Json) -ErrorAction Stop
        } else {
            $response = Invoke-RestMethod -Method $method -Uri "$baseUrl$uri" -Headers $headers -ErrorAction Stop
        }
        return $response
    } catch {
        Write-Host "Error calling $uri : $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $stream = $_.Exception.Response.GetResponseStream()
            if ($stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                Write-Host "Details: $($reader.ReadToEnd())"
            }
        }
        return $null
    }
}

Write-Host "1. Testing List Keys..."
$keys = Test-Endpoint "GET" "/admin/keys"
if ($keys) { Write-Host "Success: Retrieved keys. Count: $($keys.psobject.properties.name.Count)" } else { Write-Host "Failed to retrieve keys." }

Write-Host "2. Testing Create Key..."
$createRes = Test-Endpoint "POST" "/admin/keys/create" -body @{ type="paid"; expires_in=3600 }
if ($createRes -and $createRes.success) { 
    Write-Host "Success: Created key $($createRes.key)" 
    $newKey = $createRes.key
} else { 
    Write-Host "Failed to create key." 
    exit
}

Write-Host "3. Testing Reset HWID..."
$resetRes = Test-Endpoint "POST" "/admin/keys/reset_hwid" -body @{ key=$newKey }
if ($resetRes -and $resetRes.success) { Write-Host "Success: HWID Reset." } else { Write-Host "Failed to reset HWID." }

Write-Host "4. Testing Delete Key..."
$deleteRes = Test-Endpoint "DELETE" "/admin/keys/delete" -body @{ key=$newKey }
if ($deleteRes -and $deleteRes.success) { Write-Host "Success: Key Deleted." } else { Write-Host "Failed to delete key." }
