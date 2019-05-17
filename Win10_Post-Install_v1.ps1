# Description: Windows 10 Post Install Clean/Prep Script
# Author: Jon Childers & Chase Jones
# Last Updated: 5/17/19 1:30 pm
#
# !!!!! Set "Set-ExecutionPolicy RemoteSigned" in an elevated shell before launchiing this script: 
# 
#This will self elevate the script so with a UAC prompt since this script needs to be run as an Administrator in order to function properly.
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
    Start-Sleep 1
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

#no errors throughout
$ErrorActionPreference = 'silentlycontinue'

# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

Function InstallThese {
    #--- Install Apps ---
    choco install googlechrome
    # choco install microsoft-teams
    # 
    }

Function RemoveThese {

    #--- Uninstall unecessary applications that come with Windows out of the box ---

    # 3D Builder
    Get-AppxPackage Microsoft.3DBuilder | Remove-AppxPackage

    # Alarms
    Get-AppxPackage Microsoft.WindowsAlarms | Remove-AppxPackage

    # Autodesk
    Get-AppxPackage *Autodesk* | Remove-AppxPackage

    # Bing Weather, News, Sports, and Finance (Money):
    Get-AppxPackage Microsoft.BingFinance | Remove-AppxPackage
    Get-AppxPackage Microsoft.BingNews | Remove-AppxPackage
    Get-AppxPackage Microsoft.BingSports | Remove-AppxPackage
    Get-AppxPackage Microsoft.BingWeather | Remove-AppxPackage

    # BubbleWitch
    Get-AppxPackage *BubbleWitch* | Remove-AppxPackage

    # Calculator
    Get-AppxPackage Microsoft.WindowsCalculator | Remove-AppxPackage

    # Candy Crush
    Get-AppxPackage king.com.CandyCrush* | Remove-AppxPackage

    # Comms Phone
    Get-AppxPackage Microsoft.CommsPhone | Remove-AppxPackage

    # Dell
    Get-AppxPackage *Dell* | Remove-AppxPackage

    # Dropbox
    Get-AppxPackage *Dropbox* | Remove-AppxPackage

    # Facebook
    Get-AppxPackage *Facebook* | Remove-AppxPackage

    # Feedback Hub
    Get-AppxPackage Microsoft.WindowsFeedbackHub | Remove-AppxPackage

    # Get Started
    Get-AppxPackage Microsoft.Getstarted | Remove-AppxPackage

    # Keeper
    Get-AppxPackage *Keeper* | Remove-AppxPackage

    # Mail & Calendar
    Get-AppxPackage microsoft.windowscommunicationsapps | Remove-AppxPackage

    # Maps
    Get-AppxPackage Microsoft.WindowsMaps | Remove-AppxPackage

    # March of Empires
    Get-AppxPackage *MarchofEmpires* | Remove-AppxPackage

    # McAfee Security
    Get-AppxPackage *McAfee* | Remove-AppxPackage

    # Messaging
    Get-AppxPackage Microsoft.Messaging | Remove-AppxPackage

    # Minecraft
    Get-AppxPackage *Minecraft* | Remove-AppxPackage

    # Netflix
    Get-AppxPackage *Netflix* | Remove-AppxPackage

    # Office Lens
    Get-AppxPackage Microsoft.OfficeLens | Remove-AppxPackage

    # Office Hub
    Get-AppxPackage Microsoft.MicrosoftOfficeHub | Remove-AppxPackage

    # One Connect
    Get-AppxPackage Microsoft.OneConnect | Remove-AppxPackage

    # OneNote
    Get-AppxPackage Microsoft.Office.OneNote | Remove-AppxPackage

    # People
    Get-AppxPackage Microsoft.People | Remove-AppxPackage

    # Phone
    Get-AppxPackage Microsoft.WindowsPhone | Remove-AppxPackage

    # Plex
    Get-AppxPackage *Plex* | Remove-AppxPackage

    # Skype (Metro version)
    Get-AppxPackage Microsoft.SkypeApp | Remove-AppxPackage

    # Sound Recorder
    Get-AppxPackage Microsoft.WindowsSoundRecorder | Remove-AppxPackage

    # Solitaire
    Get-AppxPackage *Solitaire* | Remove-AppxPackage

    # SpeedTest
    Get-AppxPackage Microsoft.NetworkSpeedTest | Remove-AppxPackage

    # Sticky Notes
    Get-AppxPackage Microsoft.MicrosoftStickyNotes | Remove-AppxPackage

    # Sway
    Get-AppxPackage Microsoft.Office.Sway | Remove-AppxPackage

    #Todos
    Get-AppxPackage Microsoft.Todos | Remove-AppxPackage

    # Twitter
    Get-AppxPackage *Twitter* | Remove-AppxPackage

    #Wallet
    Get-AppxPackage Microsoft.Wallet | Remove-AppxPackage

    #Whiteboard
    Get-AppxPackage Microsoft.Whiteboard | Remove-AppxPackage

    # Xbox
    Get-AppxPackage Microsoft.XboxApp | Remove-AppxPackage
    Get-AppxPackage Microsoft.XboxGameOverlay | Remove-AppxPackage
    Get-AppxPackage Microsoft.XboxSpeechToTesxtOverlay | Remove-AppxPackage
    Get-AppxPackage Microsoft.XboxIdentityProvider | Remove-AppxPackage

    # Zune Music, Movies & TV
    Get-AppxPackage Microsoft.ZuneMusic | Remove-AppxPackage
    Get-AppxPackage Microsoft.ZuneVideo | Remove-AppxPackage
    }

Function ScheduledTasksOff {
    #Disables scheduled tasks that are considered unnecessary 
    Write-Output "Disabling scheduled tasks"
    Get-ScheduledTask  XblGameSaveTaskLogon | Disable-ScheduledTask
    Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask
    Get-ScheduledTask  Consolidator | Disable-ScheduledTask
    Get-ScheduledTask  UsbCeip | Disable-ScheduledTask
    Get-ScheduledTask  DmClient | Disable-ScheduledTask
    Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask
    }

Function ProtectPrivacy {

    #Disables Windows Feedback Experience
    Write-Output "Disabling Windows Feedback Experience program"
    $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    If (Test-Path $Advertising) {
        Set-ItemProperty $Advertising Enabled -Value 0 
    }
            
    #Stops Cortana from being used as part of your Windows Search Function
    Write-Output "Stopping Cortana from being used as part of your Windows Search Function"
    $Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    If (Test-Path $Search) {
        Set-ItemProperty $Search AllowCortana -Value 0 
    }

    #Disables Web Search in Start Menu
    Write-Output "Disabling Bing Search in Start Menu"
    $WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0 
    If (!(Test-Path $WebSearch)) {
        New-Item $WebSearch
    }
    Set-ItemProperty $WebSearch DisableWebSearch -Value 1 
            
    #Stops the Windows Feedback Experience from sending anonymous data
    Write-Output "Stopping the Windows Feedback Experience program"
    $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
    If (!(Test-Path $Period)) { 
        New-Item $Period
    }
    Set-ItemProperty $Period PeriodInNanoSeconds -Value 0        

    #Preping mixed Reality Portal for removal    
    Write-Output "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
    $Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"    
    If (Test-Path $Holo) {
        Set-ItemProperty $Holo  FirstRunSucceeded -Value 0 
    }
    
    #Disables Wi-fi Sense 
    Write-Output "Disabling Wi-Fi Sense"
    $WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    $WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
    $WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
    If (!(Test-Path $WifiSense1)) {
        New-Item $WifiSense1
    }
    Set-ItemProperty $WifiSense1  Value -Value 0 
    If (!(Test-Path $WifiSense2)) {
        New-Item $WifiSense2
    }
    Set-ItemProperty $WifiSense2  Value -Value 0 
    Set-ItemProperty $WifiSense3  AutoConnectAllowedOEM -Value 0 
    

    #Disables live tiles
    Write-Output "Disabling live tiles"
    $Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
    If (!(Test-Path $Live)) {      
        New-Item $Live
    }
    Set-ItemProperty $Live  NoTileApplicationNotification -Value 1 

    #Turns off Data Collection via the AllowTelemtry key by changing it to 0
    Write-Output "Turning off Data Collection"
    $DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    $DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"    
    If (Test-Path $DataCollection1) {
        Set-ItemProperty $DataCollection1  AllowTelemetry -Value 0 
    }
    If (Test-Path $DataCollection2) {
        Set-ItemProperty $DataCollection2  AllowTelemetry -Value 0 
    }
    If (Test-Path $DataCollection3) {
        Set-ItemProperty $DataCollection3  AllowTelemetry -Value 0 
    }

    #Disabling Location Tracking {
    Write-Output "Disabling Location Tracking"
    $SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
    $LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
    If (!(Test-Path $SensorState)) {
        New-Item $SensorState
    }
    
    Set-ItemProperty $SensorState SensorPermissionState -Value 0 
    If (!(Test-Path $LocationConfig)) {
        New-Item $LocationConfig
    }
    Set-ItemProperty $LocationConfig Status -Value 0
    }

Function Annoyances {
    Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions

    # Disable Quick Access: Recent Files
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Type DWord -Value 0
    # Disable Quick Access: Frequent Folders
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -Type DWord -Value 0
    # Change Explorer home screen back to "This PC"
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1

    # Enable and start Windows Remote Management (WS-Management)
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM" -Name Start -Type Dword -Value 2
        Start-Service WinRM

    # Enable and start Remote Registry
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name ImagePath -Type String -Value "%SystemRoot%\system32\svchost.exe -k localService -p"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name DisplayName -Type String -Value "Remote Registry"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name ObjectName -Type String -Value "NT AUTHORITY\LocalService"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name Start -Type Dword -Value 2
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name Type -Type Dword -Value 32
        Start-Service RemoteRegistry

    # Enable RDP and allow it through the firewall
        Set-RemoteDesktopConfig -Enable -ConfigureFirewall -AllowOlderClients

    # Set NumLock ON at Windows login screen
        $path = 'HKU:\.DEFAULT\Control Panel\Keyboard\'
        $name = 'InitialKeyboardIndicators'
        $value = '2'
        Set-Itemproperty -Path $path -Name $name -Value $value

    # Hide Task View button
        Write-Output "Hide Task View Button"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

    # Remove 3D Objects folder from Windows Explorer
        REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /F
        REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /F

    # Disables scheduled tasks that are considered unnecessary 
        Write-Output "Disabling scheduled tasks"
        Get-ScheduledTask  XblGameSaveTaskLogon | Disable-ScheduledTask
        Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask
        Get-ScheduledTask  Consolidator | Disable-ScheduledTask
        Get-ScheduledTask  UsbCeip | Disable-ScheduledTask
        Get-ScheduledTask  DmClient | Disable-ScheduledTask
        Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask

    # Stop and disable WAP Push Service
        Write-Output "Stopping and disabling WAP Push Service"
        Stop-Service "dmwappushservice"
        Set-Service "dmwappushservice" -StartupType Disabled

    # Change Explorer home to "This PC"
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1

    # Disable Xbox Gamebar
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type DWord -Value 0

    # Hide Fun Facts on Lockscreen
        Write-Host "Hiding Fun Facts on Lockscreen"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Type DWord -Value 0

    # Hide Search button / box
        Write-Host "Hiding Search Box / Button"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

    # Start Menu Disable Bing Search Results
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0

    # Remove Edge icon on desktop
        Write-Output "Disabling Edge Desktop Shortcut Creation"
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Type DWORD -Value 1 

    # Better File Explorer
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneExpandToCurrentFolder -Value 1        
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -Value 1       
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name MMTaskbarMode -Value 2

    # Hide Task View button
        Write-Output "Hiding Task View button"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
        
    # Stop and disable the Diagnostics Track
        Write-Output "Stopping and disabling Diagnostics Tracking Service"
        Stop-Service "DiagTrack"
        Set-Service "DiagTrack" -StartupType Disabled
    }

Function UnpinStart {
    #https://superuser.com/questions/1068382/how-to-remove-all-the-tiles-in-the-windows-10-start-menu
    #Unpins all tiles from the Start Menu
    Write-Host "Unpinning all tiles from the start menu"
    (New-Object -Com Shell.Application).
    NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').
    Items() |
        % { $_.Verbs() } |
        ? {$_.Name -match 'Un.*pin from Start'} |
        % {$_.DoIt()}
    }

# Unpins Apps from taskbar
Function UnpinApp ( [string]$appname ) {
            try {
                $exec = $false
                
                ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Unpin from taskbar'} | %{$_.DoIt(); $exec = $true}
                
                if ($exec) {
                    Write "App '$appname' unpinned from Taskbar"
                } else {
                    Write "'$appname' not found or 'Unpin from taskbar' not found on item!"
                }
                
            } catch {
                Write-Error "Error unpinning $appname from taskbar!"
            }
        }
UnPinApp "Microsoft Edge"
UnPinApp "Microsoft Store"
UnPinApp "Mail"

Function Debloater {

    $Keys = @(
                
            #Remove Background Tasks
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
                
            #Windows File
            "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                
            #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
                
            #Scheduled Tasks to delete
            "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
                
            #Windows Protocol Keys
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
                   
            #Windows Share Target
            "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        )

        #This writes the output of each key it is removing and also removes the keys listed above.
        ForEach ($Key in $Keys) {
        Write-Output "Removing $Key from registry"
        Remove-Item $Key -Recurse
    }	
    }

# Download and silent install Java Runtime Environement
    # working directory path
    $workd = "c:\temp"

    # Check if work directory exists if not create it
    If (!(Test-Path -Path $workd -PathType Container))
    { 
    New-Item -Path $workd  -ItemType directory 
    }

    #create config file for silent install
    $text = '
    INSTALL_SILENT=Enable
    AUTO_UPDATE=Enable
    SPONSORS=Disable
    REMOVEOUTOFDATEJRES=1
    '
    $text | Set-Content "$workd\jreinstall.cfg"
        
    #download executable, this is the small online installer
    $source = "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=238698_478a62b7d4e34b78b671c754eaaf38ab"
    $destination = "$workd\jreInstall.exe"
    $client = New-Object System.Net.WebClient
    $client.DownloadFile($source, $destination)

    #install silently
    Start-Process -FilePath "$workd\jreInstall.exe" -ArgumentList INSTALLCFG="$workd\jreinstall.cfg"

    # Wait 60 Seconds for the installation to finish
    Start-Sleep -s 60

    # Remove the installer
    rm -Force $workd\jre*

# Calling all functions
    InstallThese
    Start-Sleep -s 5
    RemoveThese
    Start-Sleep -s 5
    ScheduledTasksOff
    Start-Sleep -s 5
    ProtectPrivacy
    Start-Sleep -s 5
    Annoyances
    Start-Sleep -s 5
    Debloater
    Start-Sleep -s 5
    UnpinStart
    Start-Sleep -s 5
    UnPinApp

#Start Cleanup
dism /online /Cleanup-Image /StartComponentCleanup

Restart-Computer