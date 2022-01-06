#### Here is the usage doc:
#### PS D:\GitHub> .\InstallGatewayOnLocalMachine.ps1 E:\shared\bugbash\IntegrationRuntime.msi <key>
####

param([string]$path, [string]$authKey, [string]$jresource = "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=245477_4d5417147a92418ea8b615e228bb6935") # JRE 8u311

function Install-JRE([string] $source)
{
# Download and silent install Java Runtime Environement

# working directory path
  $workd = "c:\temp"

# Check if work directory exists if not create it
    If (!(Test-Path -Path $workd -PathType Container))
    {
      New-Item -Path $workd -ItemType directory
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
    $source = "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=245477_4d5417147a92418ea8b615e228bb6935"
    $destination = "$workd\jreInstall.exe"
    $client = New-Object System.Net.WebClient
    $client.DownloadFile($source, $destination)

#install silently
    Start-Process -FilePath "$workd\jreInstall.exe" -ArgumentList INSTALLCFG="$workd\jreinstall.cfg"

# Wait 120 Seconds for the installation to finish
    Start-Sleep -s 180

# Remove the installer
    rm -Force $workd\jre*
}

function Install-Gateway([string] $gwPath)
{
# uninstall any existing gateway
  UnInstall-Gateway

    Write-Host "Start Gateway installation"

    Start-Process "msiexec.exe" "/i $path /quiet /passive" -Wait
    Start-Sleep -Seconds 30

    Write-Host "Succeed to install gateway"
}

function Register-Gateway([string] $key)
{
  Write-Host "Start to register gateway with key: $key"
    & "C:\Program Files\Microsoft Integration Runtime\5.0\Shared\dmgcmd.exe" @("-EnableRemoteAccess", "8060")
    & "C:\Program Files\Microsoft Integration Runtime\5.0\Shared\dmgcmd.exe" @("-RegisterNewNode", "$key", "$env:COMPUTERNAME")
    Write-Host "Succeed to register gateway"
}

function Check-WhetherGatewayInstalled([string]$name)
{
  $installedSoftwares = Get-ChildItem "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    foreach ($installedSoftware in $installedSoftwares)
    {
      $displayName = $installedSoftware.GetValue("DisplayName")
        if($DisplayName -eq "$name Preview" -or  $DisplayName -eq "$name")
        {
          return $true
        }
    }

  return $false
}


function UnInstall-Gateway()
{
  [void](Get-WmiObject -Class Win32_Product -Filter "Name='Microsoft Integration Runtime Preview' or Name='Microsoft Integration Runtime'" -ComputerName $env:COMPUTERNAME).Uninstall()
    Write-Host "Microsoft Integration Runtime has been uninstalled from this machine."
}

function Validate-Input([string]$path, [string]$key)
{
  if ([string]::IsNullOrEmpty($path))
  {
    throw "Gateway path is not specified"
  }

  if (!(Test-Path -Path $path))
  {
    throw "Invalid gateway path: $path"
  }

  if ([string]::IsNullOrEmpty($key))
  {
    throw "Gateway Auth key is empty"
  }
}

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
      [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
  Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    Break
}

Validate-Input $path $authKey

Install-JRE $jresource
Install-Gateway $path
Register-Gateway $authKey
