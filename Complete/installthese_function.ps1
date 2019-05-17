# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco feature enable -n allowGlobalConfirmation

Function installthese {
    #--- Install Apps ---
    choco install googlechrome
    # choco install microsoft-teams
    # 
    }
