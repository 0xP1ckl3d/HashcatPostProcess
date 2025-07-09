# Hashcat Post-Processing Tool

A PowerShell utility that converts raw Hashcat NTLM‑cracking output into a clean, human‑readable report. The script merges the original NTDS (or other) hash dump with the Hashcat “hash : password” output, producing a neatly aligned *username  password* list, crack‑rate statistics and the “Top 10” most common passwords — all suitable for direct inclusion in a penetration‑testing deliverable.

---

## Table of contents

1. **Features**
2. **Prerequisites**
3. **Installation**
4. **Usage**
5. **Examples**
6. **Output explained**
7. **Licence**

---

## Features

* **Clean reporting** – aligned columns make large credential sets easy to read.
* **Crack statistics** – user and hash crack rates calculated automatically.
* **Top 10 passwords** – highlights the most common passwords for attack‑path analysis.
* **Sample preview** – first ten cracked entries printed so you can eyeball the result.
* **Colour console** – important messages colour‑coded for rapid scanning.

---

## Prerequisites

* PowerShell 7 (or Windows PowerShell 5.1) on Windows or Linux.
* Hashcat already run against your hash dump.
* Two text files:

  * Original hash file in `username:uid:lm_hash:ntlm_hash` format.
  * Cracked file in `ntlm_hash:password` format (Hashcat “—show” output).

---

## Installation

```powershell
# Clone the repo and unblock the script (Windows only)
git clone https://example.com/HashcatPostProcess.git
cd HashcatPostProcess
Unblock-File .\hashcatPostProcess.ps1
```

---

## Usage

```powershell
.\hashcatPostProcess.ps1 -f <hash_file> -c <cracked_file> -o <output_file>
.\hashcatPostProcess.ps1 -h   # Show built‑in help
```

### Parameters

| Flag | Description                                     |
| ---- | ----------------------------------------------- |
| `-f` | Path to the original hash file.                 |
| `-c` | Path to the Hashcat cracked‑password file.      |
| `-o` | Destination for the cleaned, formatted results. |
| `-h` | Display help and exit.                          |

---

## Examples

```powershell
# Standard run
.\hashcatPostProcess.ps1 -f ntds.txt -c cracked.txt -o report.txt

# Alternate filenames
.\hashcatPostProcess.ps1 -f hashes.txt -c hashcat_output.txt -o clean.txt
```

---

## Output explained

### Example run

Below is a **complete sample console session** (values and names are fictitious):

```text
======================================================================
              Hashcat Post-Processing Tool v1.0
                 NTLM Database Analysis Suite
======================================================================

[+] Found Hash file: .\ntds-enabled-users.txt
[+] Found Cracked passwords file: .\cracked.txt
[*] Processing hashcat output...
[*] Reading cracked passwords...
[*] Processing original hash database...
[*] Generating clean output...
[+] SUCCESS: Clean output generated
[+] Output file: report.txt
[+] Records processed: 650

+---------------------------------------------------------------------+
                       CRACK STATISTICS
+---------------------------------------------------------------------+
 Total Users in Database:       1200
 Users with Cracked Passwords:   650
 User Crack Rate: 650/1200 ( 54.17%)
 Unique Hashes Found:           1034
 Unique Hashes Cracked:          500
 Hash Crack Rate: 500/1034 ( 48.36%)
+---------------------------------------------------------------------+

+---------------------------------------------------------------------+
                   TOP 10 MOST USED PASSWORDS
+---------------------------------------------------------------------+
 Password1                                 63 users ( 9.69%)
 Winter2024!                               19 users ( 2.92%)
 Company123                                11 users ( 1.69%)
 Welcome01                                  9 users ( 1.38%)
 Summer2025!                                8 users ( 1.23%)
 Qwerty!23                                  7 users ( 1.08%)
 Admin!234                                  6 users ( 0.92%)
 Password123!                               6 users ( 0.92%)
 Spring2024                                 5 users ( 0.77%)
 Autumn2023?                                5 users ( 0.77%)
+---------------------------------------------------------------------+

+---------------------------------------------------------------------+
                          SAMPLE OUTPUT
+---------------------------------------------------------------------+
corp\\A.Black                 Password1
corp\\R.Taylor                Password1
corp\\M.Jones                 Password1
corp\\C.White                 Company123
corp\\D.Green                 Company123
corp\\S.Brown                 Winter2024!
corp\\A.Smith                 Winter2024!
corp\\P.Young                 Welcome01
corp\\L.Baker                 Admin!234
corp\\E.Hall                  Qwerty!23
... and 640 more entries
+---------------------------------------------------------------------+

[+] Processing complete!
```

*`report.txt`* now contains the full, neatly aligned username → password list, sorted alphabetically by password.

---

## Licence

MIT Licence.&#x20;

---
