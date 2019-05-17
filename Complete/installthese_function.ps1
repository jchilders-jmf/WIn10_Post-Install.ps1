# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

Function installthese {
    #--- Install Apps ---
    choco install googlechrome
    # choco install microsoft-teams
    # 
    }