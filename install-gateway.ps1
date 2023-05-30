#### Here is the usage doc:
#### PS D:\GitHub> .\InstallGatewayOnLocalMachine.ps1 E:\shared\bugbash\IntegrationRuntime.msi <key> # defined version mode (backwards compatibility)
#### PS D:\GitHub> .\InstallGatewayOnLocalMachine.ps1 <key> # latest version mode
#### PS D:\GitHub> .\InstallGatewayOnLocalMachine.ps1 -authKey <key> -path E:\shared\bugbash\IntegrationRuntime.msi # named parameters (non-ordered)
####
[CmdletBinding(DefaultParameterSetName = 'LatestVersion')]

param(
  [Parameter(ParameterSetName = 'DefinedVersion', Position = 0, Mandatory)]
  [ValidateScript({ Test-Path $_ -PathType Leaf })]
  [string]$path,

  [Parameter(ParameterSetName = 'DefinedVersion', Position = 1, Mandatory)]
  [Parameter(ParameterSetName = 'LatestVersion', Position = 0, Mandatory)]
  [ValidateNotNullOrEmpty()]
  [string]$authKey,

  [string]$jresource = 'https://javadl.oracle.com/webapps/download/AutoDL?BundleId=245479_4d5417147a92418ea8b615e228bb6935', # JRE 8u311
  [int]$jreinstall_timeout = 5, # minutes

  [string]$irsource = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=39717', # Integration Runtime Download Page
  [string]$irsource_filter = 'https://download.microsoft.com*msi',

  [string]$vcrsource = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=26999', # Microsoft Visual C++ 2010 Redistributable (Service Pack 1)
  [string]$vcrsource_filter = 'https://download.microsoft.com*vcredist_x64.exe',
  # original url # 'https://download.microsoft.com/download/3/2/2/3224B87F-CFA0-4E70-BDA3-3DE650EFEBA5/vcredist_x64.exe'
  
  [string]$workd = 'c:\temp' # working directory path
)

function Download-File([string]$uri, [string]$workd=$script:workd, [string]$msdl_filter, [string]$outFile)
{
  # if the download is a microsoft download page - parse it for file permalinks
  if (-not [string]::IsNullOrEmpty($msdl_filter))
  {
    Write-Verbose "Searching for `"$msdl_filter`" on download page $uri"
    $page = Invoke-WebRequest -Uri $uri -UseBasicParsing
    $uri = $page.Links.Where({$_.href -like $msdl_filter}).href | Select-Object -Unique -First 1
  }
  
  # Setting output filename 
  if (!$outFile)
  {
    $outFile = [System.Net.WebUtility]::UrlDecode($uri.Split('/')[-1])
  }

  $filename = "$workd\$outFile"
  
  write-Verbose "Downloading $uri into $filename"
  (New-Object System.Net.WebClient).downloadFile($uri,$filename)

  Print-FileInfo $filename

  return $filename
}

function Install-JRE([string]$jresource = $script:jresource, [string]$workd = $script:workd, [int]$jreinstall_timeout = $script:jreinstall_timeout)
{
# Download and silent install Java Runtime Environement
# create config file for silent install
  $text = '
    INSTALL_SILENT=Enable
    AUTO_UPDATE=Enable
    SPONSORS=Disable
    REMOVEOUTOFDATEJRES=1
    '
  $text | Set-Content "$workd\jreinstall.cfg"

# download executable, this is the small online installer
  $filename = Download-File -uri $jresource -outFile 'jreInstall.exe'

# install silently
  write-Verbose "Install JRE from $filename"
  $process = Start-Process -FilePath "$filename" -ArgumentList "INSTALLCFG=`"$workd\jreinstall.cfg`"" -Wait -PassThru

# Set a timeout for jreinstall to finish
  $timeout = (Get-Date).AddMinutes($jreinstall_timeout)

# Wait for the installation to finish
  Write-Host 'Waiting for jreinstall.exe to finish...'
  while ((Get-Process jreinstall -ErrorAction SilentlyContinue) -and ((Get-Date) -le $timeout))
  {
    Start-Sleep -Seconds 10
  }

# Try to force-kill jreinstall to prevent further install conflicts
  if (Get-Process jreinstall -ErrorAction SilentlyContinue)
  {
    Stop-Process -Name jreinstall -Force
  }

# Remove the installer
  rm -Force $workd\jre*

  Print-ExecInfo $process
}

function Install-VcRedist([string]$vcrsource = $script:vcrsource, [string]$vcrsource_filter = $script:vcrsource_filter)
{
  $filename = Download-File -uri $vcrsource -msdl_filter $vcrsource_filter

  Write-Verbose "Installing VcRedist from $filename"
  $process = Start-Process -FilePath "$filename" -ArgumentList "/Q /log $workd\vcredist.log" -Wait -PassThru
  
  Start-Sleep 2
  Print-ExecInfo $process
}

function Install-Gateway([string]$filename = $script:path, [string]$workd = $script:workd)
{
# uninstall any existing gateway
  UnInstall-Gateway

  Write-Host 'Start Gateway installation'
  
  Write-Verbose "Installing Gateway from $filename"
  
  $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $filename /quiet /passive /L*v $workd\ir.log" -Wait -PassThru
  Start-Sleep -Seconds 30

  Write-Host "Gateway installer finished with exitCode: $($process.exitcode)"

  Print-ExecInfo $process
}

function Register-Gateway([string] $key)
{
  Write-Host "Start to register gateway with key: $key"
  $executable = "C:\Program Files\Microsoft Integration Runtime\5.0\Shared\dmgcmd.exe"
  
  if (test-path $executable)
  {
    $p1 = Start-Process -FilePath $executable -ArgumentList @("-EnableRemoteAccess", "8060") -Wait -PassThru
    $p2 = Start-Process -FilePath $executable -ArgumentList @("-RegisterNewNode", "$key", "$env:COMPUTERNAME") -Wait -PassThru
  }

  switch($p1.exitCode + $p2.exitCode)
  {
    0
      {
        Write-Host "Registration with the gateway was successul"
      }
    $null
      {
        Write-Host "Register gateway impossible, executable not found"
      }
    default
      {
        Write-Host "Gateway registration exit codes $($p1.exitCode)] [$($p2.exitCode)]"
      }
  }
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
  $product = Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Microsoft Integration Runtime%'" -ComputerName . -ErrorAction SilentlyContinue
  if ($product)
  {
    Write-Verbose "Found Microsoft Integration Runtime"
    Write-Verbose "$($product | Format-Table Name, Version, IdentifyingNumber)"
    [void]$product.Uninstall()
    Write-Host "Microsoft Integration Runtime $($product.Version) has been uninstalled."
  }
  else
  {
    Write-Host "Microsoft Integration Runtime not found."
  }
}

function Print-FileInfo($filename)
{
  # get file versionInfo and 
  $info = Get-Item $filename |
    Select-Object -Expand VersionInfo |
    Select-Object FileName, FileVersion, ProductVersion |
    ForEach-Object { $_.psobject.properties } |
    ForEach-Object { "$($_.Name)=$($_.Value)" }
  
  #output a single line for better visibility
  Write-Host "$($info -join '; ')"
}

function Print-ExecInfo($processinfo)
{
  # prepare process object
  $process = $processinfo |
    Select-Object exitCode, startTime, exitTime |
    ForEach-Object { $_.psobject.properties } |
    ForEach-Object { "$($_.Name)=$($_.Value)" }

  #output a single line for better visibility
  Write-Host "$($process -join '; ')"
}

# Script starting parameters (including default)
$PsBoundParameters.path = $path
$PsBoundParameters.workd = $workd
$PsBoundParameters.authKey = $authKey
$PsBoundParameters.parameterSetName = $PSCmdlet.ParameterSetName
Write-Verbose "Parameters:$($PsBoundParameters | Out-String)"

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
      [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
  Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    Break
}

# Check if work directory exists if not create it
If (!(Test-Path -Path $workd -PathType Container))
{
  New-Item -Path $workd -ItemType directory
}

Install-VcRedist
Install-JRE
if ($PSCmdlet.ParameterSetName -eq 'LatestVersion')
{
  # if path does not exist or not set falling back to IR remote install / latest version
  $path = Download-File -uri $irsource -msdl_filter $irsource_filter
}
Install-Gateway $path
Register-Gateway $authKey

# List working dir before exit for logfile names
Write-Verbose "$(Get-ChildItem $workd|out-string)"
