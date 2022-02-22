
param([String] $keyVaultName="", [String[]] $secretNames, [String] $secretsDirectory = "C:\Secrets")

New-Item $secretsDirectory -ItemType Directory -ea 0

Install-PackageProvider NuGet -Force -verbose

if (Get-Module -ListAvailable -Name Az.Accounts) {
    Write-Host "Az.Accounts module Already Installed"
} else {
    Install-Module -Name Az.Accounts -Scope CurrentUser -Repository PSGallery -Force -verbose
}

if (Get-Module -ListAvailable -Name Az.KeyVault) {
    Write-Host "Az.KeyVault module Already Installed"
} else {
    Install-Module -Name Az.KeyVault -Scope CurrentUser -Repository PSGallery -Force -verbose
}

try {
    Add-AzAccount -identity -verbose
}
catch [Exception] {
    Add-AzAccount -identity -verbose
    $_.message
}

foreach($secretName in $secretNames) {
    Write-Host "-VaultName $keyVaultName -Name $secretName"
    Get-AzKeyVaultSecret -VaultName $keyVaultName -Name "$secretName" -AsPlainText |  Out-File -FilePath $secretsDirectory/$secretName
}
