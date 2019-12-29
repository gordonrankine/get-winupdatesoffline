#region ScriptInfo

<#

.SYNOPSIS
Provides a csv report of Windows Updates from the local computer. This will report either installed or missing updates.

.DESCRIPTION
Provides a csv report of Windows Updates from the local computer. This will report either installed or missing updates.
This script runs offline and requires a file to be downloaded from Microsoft's website in order to perform the offline scan.
The script is an enhanced version of Microsoft's VB script https://docs.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates-offline

.PARAMETER cab
This is the cab file used to determine if the Windows updates are installed or missing.
It can be downloaded from http://go.microsoft.com/fwlink/?LinkId=76054.
Note: This file changes at least once a month but the link does not change. It is recommended to download a new file every time this script is run.

.PARAMETER outDir
This is the directory where the csv reports are stored. If the directory doesn't exist it will be created.

.PARAMETER isInstalled
If set to Yes, the script will search for installed updates. If set to No, the script will search for missing updates.

.PARAMETER skipAgeCheck
[OPTIONAL] In normal operation if the file is older than 30 days the script will not continue.
If the file is between 2 and 29 days a warning will be displayed before the script continues.
If set to Yes, this skips the checking of the age of the WSUS scan file and the script will run and not display a warning.

.EXAMPLE
.\Get-WinUpdatesOffline.ps1 -cab "c:\temp\wsusscn2.cab" -outDir "c:\temp" -isInstalled No
Produces a csv report that gathers missing Windows Updates and saves the report to c:\temp

.EXAMPLE
.\Get-WinUpdatesOffline.ps1 -cab "c:\temp\wsusscn2.cab" -outDir "c:\temp" -isInstalled Yes
Produces a csv report that gathers installed Windows Updates and saves the report to c:\temp

.EXAMPLE
.\Get-WinUpdatesOffline.ps1 -cab "c:\temp\wsusscn2.cab" -outDir "c:\temp" -isInstalled No -skipAgeCheck Yes
Produces a csv report that gathers missing Windows Updates and saves the report to c:\temp. The age check for wsusscn2.cab file is not performed.

.LINK
https://github.com/gordonrankine/get-winupdatesoffline

.NOTES
License:            MIT License
Compatibility:      [Desktop] Windows 7 and above, [Server] Server 2008 R2 and above.
Author:             Gordon Rankine
Date:               28/12/2019
Version:            1.0
PSSscriptAnalyzer:  Pass

#>

#endregion ScriptInfo

#region Bindings
[cmdletbinding()]

Param(
    [Parameter(Mandatory=$True, Position=0, HelpMessage="This is the location of the wsusscn2.cab or equivalent cab file.")]
    [string]$cab,
    [Parameter(Mandatory=$True, Position=1, HelpMessage="This is the directory for the output file.")]
    [string]$outDir,
    [Parameter(Mandatory=$True, Position=2, HelpMessage="This is if the script will either search for installed or missing updates.")]
    [ValidateSet('No','Yes')]
    [string]$isInstalled,
    [Parameter(Mandatory=$False, Position=3, HelpMessage="This will skip the age check of the cab file, if set to Yes.")]
    [string]$skipAgeCheck
)
#endregion Bindings

#region Functions

    ### FUNCTION - CREATE DIRECTORY ###
    function fnCreateDir {

    <#

    .SYNOPSIS
    Creates a directory.

    .DESCRIPTION
        Creates a directory.

    .PARAMETER outDir
    This is the directory to be created.

    .EXAMPLE
    .\Create-Directory.ps1 -outDir "c:\test"
    Creates a directory called "test" in c:\

    .EXAMPLE
    .\Create-Directory.ps1 -outDir "\\COMP01\c$\test"
    Creates a directory called "test" in c:\ on COMP01

    .LINK
    https://github.com/gordonrankine/powershell

    .NOTES
        License:            MIT License
        Compatibility:      Windows 7 or Server 2008 and higher
        Author:             Gordon Rankine
        Date:               13/01/2019
        Version:            1.1
        PSSscriptAnalyzer:  Pass

    #>

        [CmdletBinding()]

            Param(

            # The directory to be created.
            [Parameter(Mandatory=$True, Position=0, HelpMessage='This is the directory to be created. E.g. C:\Temp')]
            [string]$outDir

            )

            # Create out directory if it doesnt exist
            if(!(Test-Path -path $outDir)){
                if(($outDir -notlike "*:\*") -and ($outDir -notlike "*\\*")){
                Write-Output "[ERROR]: $outDir is not a valid path. Script terminated."
                Break
                }
                    try{
                    New-Item $outDir -type directory -Force -ErrorAction Stop | Out-Null
                    Write-Output "[INFO] Created output directory $outDir"
                    }
                    catch{
                    Write-Output "[ERROR]: There was an issue creating $outDir. Script terminated."
                    Write-Output ($_.Exception.Message)
                    Write-Output ""
                    Break
                    }
            }
            # Directory already exists
            else{
            Write-Output "[INFO] $outDir already exists."
            }

    } # end fnCreateDir

    ### FUNCTION - CHECK POWERSHELL IS RUNNING AS ADMINISTRATOR ###
    function fnCheckPSAdmin {

    <#

    .SYNOPSIS
    Checks PowerShell is running as Administrator.

    .DESCRIPTION
    Checks PowerShell is running as Administrator.

    .LINK
    https://github.com/gordonrankine/powershell

    .NOTES
        License:            MIT License
        Compatibility:      Windows 7 or Server 2008 and higher
        Author:             Gordon Rankine
        Date:               19/09/2019
        Version:            1.0
        PSSscriptAnalyzer:  Pass

    #>

        try{
        $wIdCurrent = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $wPrinCurrent = New-Object System.Security.Principal.WindowsPrincipal($wIdCurrent)
        $wBdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

            if(!$wPrinCurrent.IsInRole($wBdminRole)){
            Write-Output "[ERROR] PowerShell is not running as administrator. Script terminated."
            Break
            }

        }

        catch{
        Write-Output "[ERROR] There was an unexpected error checking if PowerShell is running as administrator. Script terminated."
        Break
        }

    } # end fnCheckPSAdmin

#endregion Functions ### END FUNCTIONS ###

#region Initialize
Clear-Host

# Start stopwatch
$sw = [system.diagnostics.stopwatch]::StartNew()

# Set variables
$date = Get-Date -UFormat %Y%m%d%H%M
$domain = $env:USERDOMAIN
$hostname = $env:COMPUTERNAME

fnCheckPSAdmin
fnCreateDir $outDir
#endregion Initialize

#region Checks
    # Test input CAB file exists and is .cab
    if(!(Test-Path $cab -Include *.cab)){
    Write-Output "[ERROR] There was an issue opening '$cab', please check the path to the file and it is a .cab file. Script terminated."
    Break
    }

# Determine the age of the cab file
$fileInfo = Get-Item -Path $cab -ErrorAction SilentlyContinue
# LastWriteTime used instead of CreationTime. As CreationTime will show the date last modified by Microsoft not the date the file was copied.
$cTime = $fileInfo.LastWriteTime
$fileAge = ((Get-Date) - $cTime).days

    # Skip check if set to yes
    if ($skipagecheck.ToLower() -ne 'yes'){

        # Check timestamp of wsusscn.cab file
        if ($fileAge -gt 30){
        Write-Output "[ERROR] The WSUS scan file is $fileAge days old. Please use an up to date file. Script terminated."
        Break
        }

        # Warn user if file is not current but still within 30 days
        if (($fileAge -gt 2) -and ($fileAge -le 30)){
        Write-Output "[WARNING] The WSUS scan file is $fileAge days old. Please check for an up to date file."
        Write-Output "[WARNING] The script will continue in $timer seconds if not stopped. Press CTRL + C to stop."

        $i = 20

            while($i -ge 1){
            Clear-Host
                if($i -eq 1){
                $text = "second"
                }
                else{
                $text = "seconds"
                }

            Write-Output "[WARNING] The WSUS scan file is $fileAge days old. Please check for an up to date file."
            Write-Output "[WARNING] Script will continue in $i $text. Press CTRL + C to stop."
            Start-Sleep -Seconds 1
            $i--
            Clear-Host
            }

        Write-Output "[WARNING] Script continuing with WSUS scan file of $fileAge days old."
        }

    }

    else{
    Write-Output "[WARNING] WSUS scan file age check is skipped. Script continuing with WSUS scan file of $fileAge days old."
    }

#endregion Checks

#region CreateUpdateSession

    # Create Update Session Objects
    try{
    Write-Output "[INFO] Creating Update Session."
    $updateServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
    $updateService = $updateServiceManager.AddScanPackageService("OfflineScan", $cab, 1)
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $updateSearcher.ServerSelection = 3
    $updateSearcher.ServiceID = $updateService.ServiceID
    Write-Output "[INFO] Created Update Session."
    }
    catch{
    Write-Output "[ERROR] There was an unexpected error creating the Update Object. Script terminated."
    Write-Output "[ERROR] $($_.Exception.Message)."
    Break
    }

    # Search for updates
    try{

        if($isInstalled -eq "Yes"){
        Write-Output "[INFO] Searching for installed updates. This can take a few minutes."
        $updates = $updateSearcher.Search("IsInstalled=1")
        }
        else{
        Write-Output "[INFO] Searching for missing updates. This can take a few minutes."
        $updates = $updateSearcher.Search("IsInstalled=0")
        }

    }
    catch{
    Write-Output "[ERROR] There was an unexpected error searching for updates. Script terminated."
    Write-Output "[ERROR] $($_.Exception.Message)."
    Break
    }

# Specifiy name for file.
$outFile = "$outDir\$domain$hostname`_$date.csv"

# Output results to file.
$updates.Updates |
Select-Object @{n='ID';e={if (($_.SecurityBulletinIDs).Count -eq 0) {$_.KbArticleIds} Else {$_.SecurityBulletinIDs}}},
@{n='BulletinID';e={if (($_.SecurityBulletinIDs).Count -eq 0) {''} Else {$_.SecurityBulletinIds}}},
@{n='KBID';e={$_.KbArticleIds}},
@{n='IsInstalled';e={$_.IsInstalled}},
@{n='Severity';e={if ($_.MsrcSeverity -eq 'Critical') {"4"} elseif ($_.MsrcSeverity -eq 'Important') {"3"} elseif ($_.MsrcSeverity -eq 'Moderate') {"2"} elseif ($_.MsrcSeverity -eq 'Low') {"1"}  Else {0}}},
@{n='SeverityText';e={$_.MsrcSeverity}},
@{n='Title';e={($_.Title) -replace ",", ";"}},
@{n='InformationURL';e={$_.MoreInfoUrls}},
@{n='CVEIDs';e={if (($_.CveIDs).Count  -eq 0) {''} Else {$_.CveIDs}}},
@{n='Categories';e={$_.Categories | Select-Object -ExpandProperty Name}} | # Select-Object -ExpandProperty Name is required for PowerShell v5.
Sort-Object -Property $_.KbArticleIds | Export-Csv $outFile -NoTypeInformation -Encoding ASCII
Write-Output "[INFO] Saving report to $outFile."

#endregion CreateUpdateSession

#region Cleanup
# This is where the wsuscan gets extracted to ~730MB (as of Dec 2019) each time script is run. Remove contents after scan.
Write-Output "[INFO] Cleaning up extracted cab file."
Remove-Item "C:\Windows\SoftwareDistribution\ScanFile\" -Recurse -Force -ErrorAction SilentlyContinue
#endregion Cleanup

#region CompleteMsg
Write-Output "[INFO] Script complete in $($sw.Elapsed.Hours) hours, $($sw.Elapsed.Minutes) minutes, $($sw.Elapsed.Seconds) seconds."
#endregion CompleteMsg

#region WindowsUpdateAPIInformation

# Microsoft VB Script
# https://docs.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates-offline

# AddScanPackageService
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa386821(v=vs.85).aspx
# IUpdateService AddScanPackageService (string, string, int)
# Parameters
# bstrServiceName - A descriptive name for the scan package service.
# bstrScanFileLocation - The path of the Microsoft signed scan file that has to be registered as a service.
# flags - determines how to remove the service registration of the scan package. For possible values, see UpdateServiceOption.

# CreateUpdateSearcher
# https://msdn.microsoft.com/en-us/library/aa386515(v=vs.85).aspx

# Server Selection
# https://msdn.microsoft.com/en-us/library/aa387280(v=vs.85).aspx
# ssDefault        = 0
# ssManagedServer  = 1
# ssWindowsUpdate  = 2
# ssOthers         = 3

# Search
# https://msdn.microsoft.com/en-us/library/aa386526(v=vs.85).aspx
# IsInstalled	int(bool)
# Finds updates that are installed on the destination computer.
# "IsInstalled=1" finds updates that are installed on the destination computer.
# "IsInstalled=0" finds updates that are not installed on the destination computer.

# Update
# https://msdn.microsoft.com/en-us/library/aa386099(v=vs.85).aspx

# MSRCSeverity
# https://msdn.microsoft.com/en-us/library/windows/desktop/bb294979(v=vs.85).aspx
# 4 - Critical
# 3 - Important
# 2 - Moderate
# 1 - Low
# 0 - Unspecified

# Update Type
# https://msdn.microsoft.com/en-us/library/aa387284(v=vs.85).aspx
# utSoftware  = 1
# utDriver    = 2

#endregion WindowsUpdateAPIInformation
