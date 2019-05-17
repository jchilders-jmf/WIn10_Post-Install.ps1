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