if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))  
{  
  $arguments = "& '" +$myinvocation.mycommand.definition + "'"
  Start-Process powershell -Verb runAs -ArgumentList $arguments
  Break
}
Function Download-File($url, $path) {
	Write-Host "downloading url '$url' to '$path'"
    $client = New-Object -TypeName System.Net.WebClient
    $client.DownloadFile($url, $path)
}
#
#
#User Management Section
#
#

#Existing Users
Add-Type -AssemblyName 'System.Web'
$Users = net users | Out-String
$Users = $Users-split '\s+'
$minLength = 5 ## characters
$maxLength = 10 ## characters
$length = Get-Random -Minimum $minLength -Maximum $maxLength
$nonAlphaChars = 2
$NewExist = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
$secstr = ConvertTo-SecureString -String $NewExist -AsPlainText -Force
for ($i=6; $i -lt $Users.Count-5; $i++) {
    Write-Host $Users[$i] ":" $NewExist
    net user $Users[$i] $secstr | Out-Null #Change user passwords NEEDS ADMIN (Doesn't run in current iteration for testing)
    if (($Users[$i] -ne 'student') -and ($Users[$i] -ne 'Backup'))
    {
        try {Disable-ADAccount -Identity $Users[$i]} #Disables AD account
        catch [System.Management.Automation.CommandNotFoundException] { Write-Host $Users[$i] "AD Does Not Exist/Disable Function Not Supported" -ForegroundColor Red}
        
       try { Disable-LocalUser -Name $Users[$i]} #Disables local account
       catch [System.Management.Automation.CommandNotFoundException] { Write-Host $Users[$i] "Local Does Not Exist/Disable Function Not Supported" -ForegroundColor Red}
    }
}
#Backup User
$minLength = 7 ## characters
$maxLength = 10 ## characters
$length = Get-Random -Minimum $minLength -Maximum $maxLength
$nonAlphaChars = 3
$NewLocal = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
Write-Host "Backup:" $NewLocal
$Local = ConvertTo-SecureString -String $NewLocal -AsPlainText -Force
$computer = [System.Net.Dns]::GetHostName()
try{
	New-LocalUser -Name "Backup" -Password $Local #Trys to create local backup account
	Add-LocalGroupMember -Group "Administrators" -Member "Backup" #Trys to elevate backup account to admin
} 
catch{
	net user Backup $Local /add #Backup create user for Powershell 2.0
	net localgroup Administrators Backup /add #Backup group elevation for Powershell 2.0
} 


Read-Host -Prompt 'Press ENTER to continue. MAKE SURE YOU CAPTURED THE USERS'
#
#
#Windows Defender Section
#
#
try{
	Update-MpSignature -UpdateSource MicrosoftUpdateServer #Update Defender

	Set-MpPreference -DisableArchiveScanning 0 #ZIP/RAR Scanning
	Set-MpPreference -DisableRealtimeMonitoring $false #Realtime Monitoring
	Set-MpPreference -DisableBehaviorMonitoring $false #Behavior Monitoring
	Set-MpPreference -DisableScanningNetworkFiles $false #Network Scans
	Set-MpPreference -DisableEmailScanning $false #Email Scans
	Set-MpPreference -DisableIntrusionPreventionSystem $false #Intrusion Prevention
	Set-MpPreference -DisableAutoExclusions $false #No Auto Exclusions
	Write-Host "Windows Defender Preferences Configured: Start a scan!" #Initiates Windows Defender Scan
}
catch{
	#Support for Windows 7-
	reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Defender" /t REG_DWORD /v DisableAntiSpyware /d 0
	reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Defender" /t REG_DWORD /v DisableRoutinelyTakingAction /d 0
}
#
#
#Firewall Rules
#
#

#
#
#Git Install Section
#
#
try {git --version} #Trys Git
catch [System.Management.Automation.CommandNotFoundException]{
	
	#[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    #[System.Net.ServicePointManager]::SecurityProtocol =  [Enum]::ToObject([System.Net.SecurityProtocolType], 3072)
	Write-Host "Git is not installed!!!"
    $workdir = "c:\installer"

    # Check if work directory exists if not create it
    If (Test-Path -Path $workdir -PathType Container)
    { Write-Host "$workdir already exists" -ForegroundColor Red}
    ELSE
    { New-Item -Path $workdir  -ItemType directory | Out-Null }

	$url = "https://github.com/git-for-windows/git/releases/download/v2.31.1.windows.1/Git-2.31.1-32-bit.exe"
    #$url64 = "https://github.com/git-for-windows/git/releases/download/v2.26.2.windows.1/Git-2.26.2-64-bit.exe"
    $file = "$workdir\gitinstall.exe"

    #Check if Invoke-Webrequest exists otherwise execute WebClient
    try{
		Invoke-WebRequest $url -OutFile $file
	}
    catch{
		Write-Host "Trying alternative WebClient Download of Git..."
		Download-File -url $url -path $file
    }

    Write-Host "Installing Git: 35 seconds..."
    Start-Process -FilePath "$workdir\gitinstall.exe" -Wait -ArgumentList "/verysilent"# Start the installation

    #Remove-Item -Force $workdir\gitinstall* # Remove the installer
    Write-Host "Install Complete"
    Install-Module posh-git -Scope CurrentUser -Force
    Import-Module posh-git
}


#
#
#Repo Clone Section
#
#
Write-Host "Trying auto repo handling..."
$bluespawn = "https://github.com/ION28/BLUESPAWN"
$deepblue = "https://github.com/sans-blue-team/DeepBlueCLI"
$spawnlocation = "C:\Bluespawn"
$deeplocation = "C:\Deepblue"

If (Test-Path -Path $spawnlocation -PathType Container)
{ Write-Host "$spawnlocation already exists" -ForegroundColor Red}
ELSE
{ New-Item -Path $spawnlocation  -ItemType directory | Out-Null }

If (Test-Path -Path $deeplocation -PathType Container)
{ Write-Host "$deeplocation already exists" -ForegroundColor Red}
ELSE
{ New-Item -Path $deeplocation  -ItemType directory | Out-Null }

    $url = "https://github.com/ION28/BLUESPAWN/releases/download/v0.4.3-alpha/BLUESPAWN-client-x86.exe"
    $file = "$spawnlocation\bluespawn.exe"


    try{
		Invoke-WebRequest $url -OutFile $file
	}
    catch{
		Write-Host "Trying alternative WebClient Download of BlueSpawn..."
		Download-File -url $url -path $file
	}
git clone $deepblue $deeplocation

#
#
#Windows Update Section
#
#
sfc /scannow
#Install-Module PSWindowsUpdate
#Get-WindowsUpdate
#Install-WindowsUpdate

#
#
#Script Clean-Up Section
#
#
Read-Host -Prompt 'Press ENTER to self-destruct...'
Remove-Item $MyInvocation.MyCommand.Source #Self-Delete (Probably wont happen because of windows update)