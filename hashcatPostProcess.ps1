<#
.SYNOPSIS
    Professional Hashcat Post-Processing Tool for NTLM Database Analysis

.DESCRIPTION
    This tool processes hashcat output after cracking NTLM databases by combining
    the original hash file with cracked passwords to produce a clean, formatted
    output suitable for security assessment reports.

.PARAMETER f
    Path to the original hash file containing usernames and NTLM hashes

.PARAMETER c
    Path to the cracked passwords file from hashcat output

.PARAMETER o
    Path to the output file for clean formatted results

.PARAMETER h
    Display help information

.EXAMPLE
    .\hashcatPostProcess.ps1 -f ntds.txt -c cracked.txt -o results.txt

.EXAMPLE
    .\hashcatPostProcess.ps1 -f original_hashes.txt -c hashcat_output.txt -o clean_report.txt

.NOTES
    Author: Security Assessment Tool
    Version: 1.0
    Handles duplicate passwords across multiple users correctly
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [Alias('f')]
    [string]$HashFile,
    
    [Parameter(Mandatory=$false)]
    [Alias('c')]
    [string]$CrackedFile,
    
    [Parameter(Mandatory=$false)]
    [Alias('o')]
    [string]$OutputFile,
    
    [Parameter(Mandatory=$false)]
    [Alias('h')]
    [switch]$Help
)

# ---------- Helper Functions ----------
function Show-Usage {
    Write-Host ""
    Write-Host "+---------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|                Hashcat Post-Processing Tool v1.0                   |" -ForegroundColor Cyan
    Write-Host "+---------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|  Professional NTLM Database Analysis and Report Generation        |" -ForegroundColor Cyan
    Write-Host "+---------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host "  .\hashcatPostProcess.ps1 -f <hash_file> -c <cracked_file> -o <output_file>"
    Write-Host "  .\hashcatPostProcess.ps1 -h    (Show this help)"
    Write-Host ""
    Write-Host "PARAMETERS:" -ForegroundColor Yellow
    Write-Host "  -f    Original hash file (format: username:uid:lm_hash:ntlm_hash)"
    Write-Host "  -c    Cracked passwords file from hashcat (format: hash:password)"
    Write-Host "  -o    Output file for clean formatted results"
    Write-Host "  -h    Display this help information"
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor Yellow
    Write-Host "  .\hashcatPostProcess.ps1 -f ntds.txt -c cracked.txt -o report.txt"
    Write-Host "  .\hashcatPostProcess.ps1 -f hashes.txt -c hashcat_output.txt -o clean.txt"
    Write-Host ""
    exit 1
}

function Show-Banner {
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host "              Hashcat Post-Processing Tool v1.0                      " -ForegroundColor Green
    Write-Host "                 NTLM Database Analysis Suite                        " -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host ""
}

function Test-FileExists {
    param([string]$FilePath, [string]$Description)
    
    if (-not (Test-Path $FilePath)) {
        Write-Host "[X] ERROR: $Description file not found: $FilePath" -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Found $Description`: $FilePath" -ForegroundColor Green
}

function Show-Statistics {
    param(
        [int]$TotalUsers,
        [int]$CrackedUsers,
        [int]$TotalHashes,
        [int]$CrackedHashes,
        [array]$CrackedUserData
    )
    
    $crackPercentage = if ($TotalUsers -gt 0) { [math]::Round(($CrackedUsers / $TotalUsers) * 100, 2) } else { 0 }
    $hashPercentage = if ($TotalHashes -gt 0) { [math]::Round(($CrackedHashes / $TotalHashes) * 100, 2) } else { 0 }
    
    Write-Host ""
    Write-Host "+---------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "                       CRACK STATISTICS                               " -ForegroundColor Cyan
    Write-Host "+---------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host " Total Users in Database:       $($TotalUsers.ToString().PadLeft(4))                             " -ForegroundColor White
    Write-Host " Users with Cracked Passwords:  $($CrackedUsers.ToString().PadLeft(4))                             " -ForegroundColor Green
    Write-Host " User Crack Rate: $($CrackedUsers.ToString().PadLeft(3))/$($TotalUsers.ToString().PadLeft(4)) ($($crackPercentage.ToString().PadLeft(6))%)                         " -ForegroundColor Yellow
    Write-Host " Unique Hashes Found:           $($TotalHashes.ToString().PadLeft(4))                             " -ForegroundColor White
    Write-Host " Unique Hashes Cracked:         $($CrackedHashes.ToString().PadLeft(4))                             " -ForegroundColor Green
    Write-Host " Hash Crack Rate: $($CrackedHashes.ToString().PadLeft(3))/$($TotalHashes.ToString().PadLeft(4)) ($($hashPercentage.ToString().PadLeft(6))%)                         " -ForegroundColor Yellow
    Write-Host "+---------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
    
    # Calculate top 10 most used passwords
    if ($CrackedUserData.Count -gt 0) {
        $passwordCounts = $CrackedUserData | Group-Object -Property Password | Sort-Object Count -Descending | Select-Object -First 10
        
        Write-Host "+---------------------------------------------------------------------+" -ForegroundColor Magenta
        Write-Host "                   TOP 10 MOST USED PASSWORDS                        " -ForegroundColor Magenta
        Write-Host "+---------------------------------------------------------------------+" -ForegroundColor Magenta
        
        foreach ($pwGroup in $passwordCounts) {
            $password = $pwGroup.Name
            $count = $pwGroup.Count
            $percentage = [math]::Round(($count / $CrackedUserData.Count) * 100, 2)
            
            # Truncate password if too long for display
            $displayPassword = if ($password.Length -gt 35) { $password.Substring(0, 32) + "..." } else { $password }
            
            Write-Host " $($displayPassword.PadRight(40)) $($count.ToString().PadLeft(3)) users ($($percentage.ToString().PadLeft(5))%) " -ForegroundColor White
        }
        
        Write-Host "+---------------------------------------------------------------------+" -ForegroundColor Magenta
        Write-Host ""
    }
}

# ---------- Main Script Logic ----------

# Show help if requested
if ($Help) {
    Show-Usage
}

# Show usage if no parameters provided
if (-not $HashFile -or -not $CrackedFile -or -not $OutputFile) {
    Show-Usage
}

# Display banner
Show-Banner

# Validate input files
Test-FileExists -FilePath $HashFile -Description "Hash file"
Test-FileExists -FilePath $CrackedFile -Description "Cracked passwords file"

Write-Host "[*] Processing hashcat output..." -ForegroundColor Yellow

# ---------- Build hash to password mapping ----------
Write-Host "[*] Reading cracked passwords..." -ForegroundColor Cyan
$pwMap = @{}
$crackedHashCount = 0

Get-Content $CrackedFile | ForEach-Object {
    if ($_ -match '^(?<hash>[0-9A-Fa-f]{32}):(?<pw>.*)$') {
        $hash = $matches.hash.ToLower()
        $pw = $matches.pw.Trim()
        if ($pw) {
            $pwMap[$hash] = $pw
            $crackedHashCount++
        }
    }
}

# ---------- Process original hash file ----------
Write-Host "[*] Processing original hash database..." -ForegroundColor Cyan
$crackedUsers = @()
$totalUsers = 0
$uniqueHashes = @{}

Get-Content $HashFile | ForEach-Object {
    $fields = $_ -split ':'
    if ($fields.Count -ge 4) {
        $user = $fields[0]
        $ntHash = $fields[3].ToLower()
        $totalUsers++
        
        # Track unique hashes
        $uniqueHashes[$ntHash] = $true
        
        if ($pwMap.ContainsKey($ntHash)) {
            $pw = $pwMap[$ntHash]
            if ($pw) {
                $crackedUsers += [PSCustomObject]@{
                    Username = $user
                    Password = $pw
                }
            }
        }
    }
}

# ---------- Generate clean output ----------
Write-Host "[*] Generating clean output..." -ForegroundColor Cyan

if ($crackedUsers.Count -eq 0) {
    Write-Host "[!] WARNING: No cracked passwords found to process!" -ForegroundColor Yellow
    Write-Host "[X] Output file not created." -ForegroundColor Red
    exit 1
}

# Calculate maximum username width for formatting
$maxWidth = ($crackedUsers | ForEach-Object { $_.Username.Length } | Measure-Object -Maximum).Maximum

# Sort by password and create formatted output
$outputContent = $crackedUsers | Sort-Object Password | ForEach-Object {
    "{0,-$maxWidth}  {1}" -f $_.Username, $_.Password
}

# Write to output file
$outputContent | Set-Content $OutputFile

Write-Host "[+] SUCCESS: Clean output generated" -ForegroundColor Green
Write-Host "[+] Output file: $OutputFile" -ForegroundColor White
Write-Host "[+] Records processed: $($crackedUsers.Count)" -ForegroundColor White

# ---------- Display Results ----------
Show-Statistics -TotalUsers $totalUsers -CrackedUsers $crackedUsers.Count -TotalHashes $uniqueHashes.Count -CrackedHashes $crackedHashCount -CrackedUserData $crackedUsers

# Show sample of output
if ($crackedUsers.Count -gt 0) {
    
    Write-Host "+---------------------------------------------------------------------+" -ForegroundColor DarkBlue
    Write-Host "                          SAMPLE OUTPUT                                " -ForegroundColor DarkBlue
    Write-Host "+---------------------------------------------------------------------+" -ForegroundColor DarkBlue

    $outputContent | Select-Object -First 10 | ForEach-Object {
        Write-Host "$_" -ForegroundColor White
    }
    if ($crackedUsers.Count -gt 10) {
        Write-Host "... and $($crackedUsers.Count - 10) more entries" -ForegroundColor Gray
    }
    Write-Host "+---------------------------------------------------------------------+" -ForegroundColor DarkBlue
    Write-Host ""
}

Write-Host ""
Write-Host "[+] Processing complete!" -ForegroundColor Green
Write-Host ""
