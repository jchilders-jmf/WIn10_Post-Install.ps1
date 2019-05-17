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
    Get-AppxPackage king.com.CandyCrushSaga | Remove-AppxPackage
    Get-AppxPackage king.com.CandyCrushSodaSaga | Remove-AppxPackage
    Get-AppxPackage king.com.BubbleWitch3Saga | Remove-AppxPackage

    # Comms Phone
    Get-AppxPackage Microsoft.CommsPhone | Remove-AppxPackage

    # Dell
    Get-AppxPackage *Dell* | Remove-AppxPackage

    # DolbyAccess
    Get-AppxPackage DolbyLaboratories.DolbyAccess | Remove-AppxPackage

    # DrawboardPDF
    Get-AppxPackage Drawboard.DrawboardPDF | Remove-AppxPackage

    # Dropbox
    Get-AppxPackage *Dropbox* | Remove-AppxPackage

    # Facebook
    Get-AppxPackage *Facebook* | Remove-AppxPackage

    # Feedback Hub
    Get-AppxPackage Microsoft.WindowsFeedbackHub | Remove-AppxPackage
    
    # Flipboard
    Get-AppxPackage Flipboard.Flipboard | Remove-AppxPackage

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

    # RoyalRevolt2
    Get-AppxPackage flaregamesGmbH.RoyalRevolt2 | Remove-AppxPackage

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

    # Todos
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