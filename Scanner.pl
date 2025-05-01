# Remote Security Scanner - Encrypted Version
# For scanning other systems remotely

function Invoke-RemoteScan {
param(
[string]$targetSystem,
[string]$username,
[string]$password
)

# Create a remote session with encryption
$securePass = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($username, $securePass)

$session = New-PSSession -ComputerName $targetSystem -Credential $cred -Authentication Negotiate -SessionOption (New-PSSessionOption -NoMachineProfile)

# Scan script (to be run on the target system)
$scanScript = {
function Encrypt-Data {
param([string]$data)
$bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
$secure = ConvertTo-SecureString -String $data -AsPlainText -Force
return ConvertFrom-SecureString  -SecureString $secure -Key (1..16)
}

# Gather system information
$systemInfo = systeminfo
$hotfixes = Get-HotFix
$services = Get-Service |  Where-Object {$_.Status -eq "Running"}
$network = netstat -ano
$software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*

# Identify common vulnerabilities
$vulns = @()
$vulns += "Old OS: $((Get-CimInstance Win32_OperatingSystem).Version)"
$vulns += "Critical updates not installed: $(($hotfixes | Where-Object {$_.InstalledOn -lt (Get-Date).AddMonths(-6)}).Count"
$vulns += "Vulnerable services: $(($services | Where-Object {$_.DisplayName -match 'Telnet|SMBv1|RDP'}).Count"
$vulns += "Dangerous software: $(($software | Where-Object {$_.DisplayName -match 'Java|Flash|Adobe Reader' -and $_.DisplayVersion -lt  '20.0'}).Count)"

# Encrypt results
$results = @{
SystemInfo = Encrypt-Data $systemInfo
Vulnerabilities = Encrypt-Data ($vulns -join "`n")
NetworkInfo = Encrypt-Data $network
InstalledSoftware = Encrypt-Data ($software | Out-String)
}

return $results
}

# Run scan on target system
$encryptedResults = Invoke-Command -Session $session -ScriptBlock $scanScript

# Save results
$outputFile = "$env:TEMP\remote_scan_$(Get-Date -Format 'yyyyMMddHHmmss').enc"
$encryptedResults | ConvertTo-Json -Depth 5 | Out-File $outputFile

# Clear session
Remove-PSSession $session

return "Scan complete. Encrypted results saved to $outputFile."
 }

# Usage:
# Invoke-RemoteScan -targetSystem "192.168.1.100" -username "DOMAIN\user" -password "P@ssw0rd"
