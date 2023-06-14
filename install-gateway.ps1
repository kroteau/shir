#### Here is the usage doc:
#### PS D:\GitHub> .\InstallGatewayOnLocalMachine.ps1 E:\shared\bugbash\IntegrationRuntime.msi <key>                # Backwards Compatibility mode
#### PS D:\GitHub> .\InstallGatewayOnLocalMachine.ps1 -authKey <key> -path E:\shared\bugbash\IntegrationRuntime.msi # also possible to call in named (non-ordered) way
#### PS D:\GitHub> .\InstallGatewayOnLocalMachine.ps1 -authKey <key>                                                # get "Latest" mode, download IR from MS download
####
[CmdletBinding(DefaultParameterSetName = 'Compatibility')]

param(
  [Parameter(ParameterSetName = 'Compatibility', Position = 0, Mandatory)]
  [ValidateScript({ Test-Path $_ -PathType Leaf })]
  [string]$path,

  [Parameter(ParameterSetName = 'Latest', Position = 0, Mandatory)]
  [ValidateNotNullOrEmpty()]
  [string]$authKey,

  [Parameter(ParameterSetName = 'Compatibility', Position = 1, Mandatory)]
  [ValidateNotNullOrEmpty()]
  [string]$authKey1, # workaround for compatibility (path+key) input

  [string]$jresource = 'https://javadl.oracle.com/webapps/download/AutoDL?BundleId=245479_4d5417147a92418ea8b615e228bb6935', # JRE 8u311
  [int]$jreinstall_timeout = 5, # minutes

  [string]$irsource = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=39717', # Integration Runtime Download Page
  [string]$irsource_filter = 'https://download.microsoft.com*msi',

  [string]$vcrsource = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=26999', # Microsoft Visual C++ 2010 Redistributable (Service Pack 1)
  [string]$vcrsource_filter = 'https://download.microsoft.com*vcredist_x64.exe',
  # original url # 'https://download.microsoft.com/download/3/2/2/3224B87F-CFA0-4E70-BDA3-3DE650EFEBA5/vcredist_x64.exe'
  
  [string]$workd = 'c:\temp' # working directory path
)

function Download-File([string]$uri, [string]$workd=$script:workd, [string]$msdl_filter, [string]$outFile) {
  # if the download is a microsoft download page - parse it for file permalinks
  if (-not [string]::IsNullOrEmpty($msdl_filter)) {
    Write-Verbose "Searching for `"$msdl_filter`" on download page $uri"
    $page = Invoke-WebRequest -Uri $uri -UseBasicParsing
    $uri = $page.Links.Where({$_.href -like $msdl_filter}).href | Select-Object -Unique -First 1
  }
  
  # Setting output filename 
  if (!$outFile) {
    $outFile = [System.Net.WebUtility]::UrlDecode($uri.Split('/')[-1])
  }

  # we'd need full path further
  $filename = "$workd\$outFile"
  
  Write-Verbose "Downloading $uri into $filename"
  (New-Object System.Net.WebClient).downloadFile($uri,$filename)

  # unfortunately does not work for MSI packages, only for EXE
  Print-ObjectInfo -psObject ((Get-Item $filename).VersionInfo) -propertyNames @('FileName','FileVersion','ProductVersion')

  return $filename
}

function Install-JRE([string]$jresource = $script:jresource, [string]$workd = $script:workd, [int]$jreinstall_timeout = $script:jreinstall_timeout) {
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
  Write-Verbose "Install JRE from $filename"

  Invoke-Installer -FilePath "$filename" -ArgumentList "INSTALLCFG=`"$workd\jreinstall.cfg`""
# Unfortunately JRE gives back the console and continues installing in background for some time
# Waiting for background jreinstall process

# Set a timeout for jreinstall to finish
  $timeout = (Get-Date).AddMinutes($jreinstall_timeout)

# Wait for the installation to finish and print a '.' each 10 seconds of waiting
  Write-Host -NoNewLine 'Waiting for jreinstall.exe to finish'
  while ((Get-Process jreinstall -ErrorAction SilentlyContinue) -and ((Get-Date) -le $timeout)) {
    Write-Host -NoNewLine '.'
    Start-Sleep -Seconds 10
  }
  Write-Host '' # just a new line to fix console output after NoNewLine

# Try to force-kill jreinstall to prevent further install conflicts
  if (Get-Process jreinstall -ErrorAction SilentlyContinue) {
    Stop-Process -Name jreinstall -Force
  }

# Remove the installer
  rm -Force $workd\jre*
}

function Install-VcRedist([string]$vcrsource = $script:vcrsource, [string]$vcrsource_filter = $script:vcrsource_filter) {
  $filename = Download-File -uri $vcrsource -msdl_filter $vcrsource_filter

  Write-Verbose "Installing VcRedist from $filename"
  
  Invoke-Installer -FilePath "$filename" -ArgumentList "/Q /log $workd\vcredist.log"
}

function Install-Gateway([string]$filename = $script:path, [string]$workd = $script:workd) {
# uninstall any existing gateway
  UnInstall-Gateway
  
  Write-Verbose "Installing Gateway from $filename"

  Invoke-Installer -FilePath 'msiexec.exe' -ArgumentList "/i $filename /quiet /passive /L*v $workd\ir.log"
}

function Register-Gateway([string] $key) {
  Write-Host "Start to register gateway with key: $key"

  $executable = "C:\Program Files\Microsoft Integration Runtime\5.0\Shared\dmgcmd.exe"
  
  if (test-path $executable) {
    $p1 = Start-Process -FilePath $executable -ArgumentList @("-EnableRemoteAccess", "8060") -Wait -PassThru
    $p2 = Start-Process -FilePath $executable -ArgumentList @("-RegisterNewNode", "$key", "$env:COMPUTERNAME") -Wait -PassThru
  }

  switch($p1.exitCode + $p2.exitCode) {
    0 {
      Write-Host "Registration with the gateway was successul"
    }
    $null {
      Write-Host "Register gateway impossible, executable not found"
    }
    default {
      Write-Host "Gateway registration exit codes $($p1.exitCode)] [$($p2.exitCode)]"
    }
  }
}

function UnInstall-Gateway() {
# searching WMI for any integration runtime and performing uninstall
  $product = Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Microsoft Integration Runtime%'" -ComputerName . -ErrorAction SilentlyContinue
  if ($product) {
    Write-Verbose "Found Microsoft Integration Runtime`n$($product | Format-Table Name, Version, IdentifyingNumber)"
    [void]$product.Uninstall()
    Write-Host "Microsoft Integration Runtime $($product.Version) has been uninstalled."
  } else {
    Write-Host "Microsoft Integration Runtime not found."
  }
}

function Invoke-Installer([Parameter(Mandatory=$true)][string]$FilePath, [string]$ArgumentList) {
# wraps around start-process to get some useful info from the executed process
  $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru -Wait

  Print-ObjectInfo -psObject $process -propertyNames @('StartTime','ExitTime','ExitCode')
}

function Print-ObjectInfo([object]$psObject, [string[]]$propertyNames) {
# extracts properties from a powershell object and outputs them to the console
  $info = $psObject |
    ForEach-Object {
      $_.psobject.properties |
        Where-Object { $propertyNames -contains $_.Name } |
          ForEach-Object { "$($_.Name)=$($_.Value)" }
    }

  Write-Host "$($info -join '; ')"
}

# Script starting parameters (including default)
$CommandName = $PSCmdlet.MyInvocation.InvocationName # get the script own name
$ParameterList = (Get-Command -Name $CommandName).Parameters # Get the list of parameters for the script
$inputParams = ForEach ($Parameter in $ParameterList) {
# extract parameter=value and put into inputParams for the report below
  Get-Variable -Name $Parameter.Values.Name -ErrorAction SilentlyContinue | Select-object Name,Value
}
$startupreport = @(
  "ParameterSetName:  $($PSCmdlet.ParameterSetName)",
  "ParameterCount:    $($PSBoundParameters.Count)",
  "PsBoundParameters: $($PsBoundParameters.getEnumerator())",
  "Script parameters (and their defaults):$($inputParams|Out-String)"
)
Write-Verbose "`n$($startupreport -join "`n")"

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
      [Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Write-Error -Category PermissionDenied -Message "You do not have Administrator rights to run this script!`n Please re-run this script as an Administrator!"
  Break
}

# Working directory tests/creation
If (-NOT (Test-Path -Path $workd -PathType Container)) {
  New-Item -Path $workd -ItemType Directory | Out-Null
    if ($?) {
      Write-Host "Created directory: $workd"
    } else {
      Write-Host "Failed to create directory: $workd"
    }
}

Install-VcRedist
Install-JRE
switch ($PSCmdlet.ParameterSetName) {
  'Latest' {
    # if path does not exist or not set falling back to IR remote install / latest version
    $path = Download-File -uri $irsource -msdl_filter $irsource_filter
  }
  'Compatibility' {
    # Compatibility mode uses positional parameter w/ a different name because of PS param handling limitations
    $authKey = $authKey1
  }
}
Install-Gateway $path
Register-Gateway $authKey

# List working dir before exit for logfile names
Write-Verbose "$((Get-ChildItem $workd|Out-String -Width 100).Trim())"
