param (
    [switch]$Quiet,  #Only print findings
    [switch]$Users,   #Only check user dirs
    [string]$Dir     #Only check specific dir
)

# File types to look for
$fileTypes = @("*.ini", "*.config", "*.xml", "*.json", "*.txt", "*.log", "*.env", "*.yml", "*.credentials", "*.settings", "*.php", "*.asp", "*.js", "*.py", "*.bat", "*.sh", "*.settings", "*.ps1")

$allUserDirs = @(
Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
)

# Array to hold dirs to scan depending on arguments
$directories = @()

if (-not $Dir) {
	foreach ($user in $allUserDirs){
		$directories += "$user\Desktop"
		$directories += "$user\Documents"
		$directories += "$user\Downloads"
		$directories += "$user\AppData\Roaming"
		$directories += "$user\AppData\Local"
	}
}

if (-not $Users -and -not $Dir) {
	$directories += "C:\Users\Public"
	$directories += "C:\ProgramData"
	$directories += "C:\Program Files"
	$directories += "C:\Program Files (x86)"
}

if ($dir) {
	$directories += "$dir"
}

# Directories to exclude
$excludedDirs = @(
    "C:\Windows", "C:\Windows\System32", "C:\Windows\SysWOW64"
)

# Regex patterns for sensitive information (only looking for keywords)
$patterns = @(
    "\bpassword\b",      
    "\bpwd\b",           
    "\bapi[_-]?key\b",   
    "\bsecret\b",        
    "\btoken\b",         
    "\baws[_-]?access[_-]?key[_-]?id\b",
    "\baws[_-]?secret[_-]?access[_-]?key\b",
    "\bbearer\b",        
    "\bclient[_-]?secret\b" 
)

# Function to scan a file for credentials
function Scan-File {
    param ($filePath)

    $content = Get-Content -Path $filePath -ErrorAction SilentlyContinue
    $found = $false

    if ($content) {
        foreach ($line in $content) {
            foreach ($pattern in $patterns) {
                if ($line -match $pattern) {
                    $trimmedLine = $line.Substring(0, [Math]::Min(100, $line.Length))  # Limit output to 100 chars
                    Write-Host "[!] Potential credential found in: $filePath" -ForegroundColor Red
                    Write-Host "    → Match: $trimmedLine" -ForegroundColor Yellow
                    $found = $true
                    break  # Stop checking after the first match in this file
                }
            }
            if ($found) { break }  # Stop checking after the first match in this file
        }
    }

    if (-not $found -and -not $Quiet) {
        Write-Host "[✅] No credentials found in: $filePath" -ForegroundColor Green
    }
}

# Function to scan directories
function Scan-Directories {
    foreach ($dir in $directories) {
        if (Test-Path $dir) {
            if ($excludedDirs -notcontains $dir) {
                if (-not $Quiet) { Write-Host "[*] Scanning: $dir" }
                try {
                    Get-ChildItem -Path $dir -Recurse -Include $fileTypes -ErrorAction SilentlyContinue | ForEach-Object {
                        Scan-File $_.FullName
                    }
                } catch {
                    if (-not $Quiet) {
                        Write-Host "[!] Skipping inaccessible directory: $dir" -ForegroundColor Yellow
                    }
                }
            }
        }
    }
}

# Start scanning
if (-not $Quiet) { Write-Host "`n[+] Starting security audit for hardcoded credentials...`n" -ForegroundColor Green }
Scan-Directories
if (-not $Quiet) { Write-Host "`n[+] Scan complete!`n" -ForegroundColor Cyan }
