# ==============================================
# Windows Logon Event Viewer Script
# ==============================================

# Event ID Reference:
# 4624 -> Successful logon
# 4625 -> Failed logon attempt
# 4634 -> Logoff event (session ended)
# 4647 -> User-initiated logoff (manual sign-out)
# Source: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-ids

# Common System Accounts You Might See:
# DWM-1  -> Desktop Window Manager (handles Windows visual effects)
# UMFD-0 -> User Mode Font Driver Host (system font rendering service)
# UMFD-1 -> Another instance of the same font driver service
# These are normal system processes, not real users.
# You can safely ignore them when analyzing human logins.
# Sources:
# https://learn.microsoft.com/en-us/windows/win32/dwm/dwm-overview
# https://learn.microsoft.com/en-us/windows/win32/printdocs/umdf-driver-model-overview

# ==============================================

# Get successful logon events (ID 4624)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} |
  ForEach-Object {
    $user = $_.Properties[5].Value        # Extract username
    $logonType = $_.Properties[8].Value   # Extract logon type (e.g., 2 = Local, 10 = RDP)
    [PSCustomObject]@{
      Time       = $_.TimeCreated
      User       = $user
      LogonType  = $logonType
    }
  } |
  Where-Object { $_.LogonType -in 2,10 } | # Only local (2) and RDP (10) logins
  Sort-Object Time -Descending
