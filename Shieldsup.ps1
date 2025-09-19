<#
.SYNOPSIS
  Recovery script to undo the changes made by the "disable Defender / disable updates / disable UAC" script.

.DESCRIPTION
  - Restores EnableLUA (UAC)
  - Removes Policies keys under HKLM:\Software\Policies\Microsoft\Windows Defender and related subkeys
  - Removes WindowsUpdate AU policy created under Policies
  - Removes the registry Run entries that were cleared by the disabling script
  - Sets SecurityHealthService startup back to automatic (2) and attempts to start it
  - Re-enables and starts Windows Update service (wuauserv) and sets StartupType to Manual (trigger-start)
  - Attempts to start WinDefend and re-enable Defender realtime if Defender cmdlets are present
  - Resets LocalAccountTokenFilterPolicy to 0 (Remote UAC)
#>

# ----------- Helper / safety checks -----------
function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "This script must be run as Administrator. Right-click PowerShell and choose 'Run as administrator'."
        exit 1
    }
}

Assert-Admin

# Convenience variables
$policiesBase = "HKLM:\SOFTWARE\Policies\Microsoft"
$defenderPolicies = Join-Path $policiesBase "Windows Defender"
$winUpdatePoliciesAU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$runKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$defenderRunNames = @("Windows Defender", "Windows Defender Scheduled Scan", "Windows Defender Verification")

Write-Host "Starting recovery... (some steps may require a reboot to fully apply)" -ForegroundColor Cyan

# ----------- 1) Restore UAC -----------
try {
    Write-Host "Restoring EnableLUA (UAC) = 1 ..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord -ErrorAction Stop
} catch {
    Write-Warning "Failed to set EnableLUA: $_"
}

# ----------- 2) Restore SecurityHealthService startup -----------
try {
    # Typical default for SecurityHealthService is Automatic (2). If you prefer 'Automatic (Delayed Start)' you can adjust.
    Write-Host "Setting SecurityHealthService Start to 2 (Automatic) ..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\SecurityHealthService" -Name "Start" -Value 2 -Type DWord -ErrorAction Stop
} catch {
    Write-Warning "Failed to set SecurityHealthService Start value: $_"
}

# Attempt to start the service
try {
    Write-Host "Starting SecurityHealthService (if present) ..."
    Start-Service -Name SecurityHealthService -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Could not start SecurityHealthService: $_"
}

# ----------- 3) Remove Defender policy keys (so Windows will use defaults) -----------
if (Test-Path $defenderPolicies) {
    try {
        Write-Host "Removing policy key: $defenderPolicies (this will remove DisableAntiSpyware / DisableAntiVirus / Real-Time Protection policy values) ..."
        Remove-Item -Path $defenderPolicies -Recurse -Force -ErrorAction Stop
    } catch {
        Write-Warning "Failed to remove $defenderPolicies: $_"
    }
} else {
    Write-Host "No Defender policy key found at $defenderPolicies — skipping removal."
}

# Also remove any MpEngine, SpyNet, Reporting subkeys if they exist separately (safe due to -Recurse)
$subkeys = @("MpEngine","Real-Time Protection","Reporting","SpyNet")
foreach ($sub in $subkeys) {
    $path = Join-Path $defenderPolicies $sub
    if (Test-Path $path) {
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            Write-Host "Removed $path"
        } catch {
            Write-Warning "Failed to remove $path: $_"
        }
    }
}

# ----------- 4) Remove WindowsUpdate AU policy if present -----------
if (Test-Path $winUpdatePoliciesAU) {
    try {
        Write-Host "Removing Windows Update AU policy: $winUpdatePoliciesAU ..."
        Remove-Item -Path $winUpdatePoliciesAU -Recurse -Force -ErrorAction Stop
    } catch {
        Write-Warning "Failed to remove $winUpdatePoliciesAU: $_"
    }
} else {
    Write-Host "No Windows Update AU policy found — skipping."
}

# If the WindowsUpdate parent key is empty, optionally remove it (safe)
$winUpdateParent = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
if (Test-Path $winUpdateParent) {
    try {
        $children = Get-ChildItem -Path $winUpdateParent -ErrorAction SilentlyContinue
        if (-not $children) {
            Remove-Item -Path $winUpdateParent -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Removed empty WindowsUpdate parent policy key."
        }
    } catch { }
}

# ----------- 5) Remove/restore Run autorun entries for Defender (they were set to empty string) -----------
foreach ($r in $defenderRunNames) {
    try {
        if (Get-ItemProperty -Path $runKey -Name $r -ErrorAction SilentlyContinue) {
            Write-Host "Removing $r entry from $runKey ..."
            Remove-ItemProperty -Path $runKey -Name $r -ErrorAction SilentlyContinue
        } else {
            Write-Host "No Run entry named '$r' exists (or already removed)."
        }
    } catch {
        Write-Warning "Failed to remove Run entry $r: $_"
    }
}

# ----------- 6) Re-enable and start Windows Update service -----------
try {
    Write-Host "Setting wuauserv StartupType to Manual (trigger-start) and starting service ..."
    # Set to Manual (Trigger Start) - PS Set-Service supports Manual/Automatic/Disabled
    Set-Service -Name wuauserv -StartupType Manual -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    Write-Host "wuauserv set to Manual and started (if present)."
} catch {
    Write-Warning "Failed to configure/start wuauserv: $_"
}

# ----------- 7) Try to start Defender service(s) and re-enable realtime if possible -----------
# Start the Microsoft Defender service (WinDefend) and SecurityCenter / Health service we already attempted above
$servicesToStart = @("WinDefend","SecurityHealthService")
foreach ($svc in $servicesToStart) {
    try {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Write-Host "Attempting to set service '$svc' StartupType to Automatic and start it..."
            Set-Service -Name $svc -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name $svc -ErrorAction SilentlyContinue
        } else {
            Write-Host "Service $svc not present on this system."
        }
    } catch {
        Write-Warning "Could not start/configure service $svc: $_"
    }
}

# If Defender PowerShell cmdlets are available, try to re-enable realtime protection
if (Get-Command -Name Set-MpPreference -ErrorAction SilentlyContinue) {
    try {
        Write-Host "Defender cmdlets found: attempting to re-enable realtime protection preferences..."
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableOnAccessProtection $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
        Write-Host "Set-MpPreference calls completed (may require service restart)."
    } catch {
        Write-Warning "Set-MpPreference failed or insufficient rights: $_"
    }

    # Restart WinDefend to apply changes
    try {
        Restart-Service -Name WinDefend -Force -ErrorAction SilentlyContinue
    } catch { }
} else {
    Write-Host "Windows Defender PowerShell cmdlets not present. Policies removed and services started where possible; Defender should return to defaults after a reboot."
}

# ----------- 8) Reset Remote UAC (LocalAccountTokenFilterPolicy) -----------
try {
    $remoteUacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if (Get-ItemProperty -Path $remoteUacPath -Name "LocalAccountTokenFilterPolicy" -ErrorAction SilentlyContinue) {
        Write-Host "Resetting LocalAccountTokenFilterPolicy to 0 ..."
        Set-ItemProperty -Path $remoteUacPath -Name "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    } else {
        Write-Host "LocalAccountTokenFilterPolicy not present; nothing to reset."
    }
} catch {
    Write-Warning "Could not reset LocalAccountTokenFilterPolicy: $_"
}

# ----------- 9) Final messages and reboot recommendation -----------
Write-Host "`nRecovery steps completed (best-effort)." -ForegroundColor Green
Write-Host "Notes:" -ForegroundColor Yellow
Write-Host " - Some changes (UAC: EnableLUA) require a reboot to take full effect."
Write-Host " - If this machine is domain-joined and Group Policy is setting Defender/Update policies, these keys may be recreated by Group Policy. In that case, undoing at the GPO level is required."
Write-Host "`nWould you like to reboot now? (Y/N)"

$choice = Read-Host
if ($choice.Trim().ToUpper() -eq "Y") {
    Write-Host "Rebooting now..."
    Restart-Computer -Force
} else {
    Write-Host "Please reboot the machine when convenient to fully apply changes."
}
