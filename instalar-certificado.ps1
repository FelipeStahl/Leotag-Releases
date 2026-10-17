#Requires -RunAsAdministrator
# Confia, nesta máquina, no certificado Authenticode autoassinado que assina o Etiqueta (opcional).
# Executar uma vez por máquina, em PowerShell aberto como administrador, com a impressão digital
# publicada nas notas da release:
#   powershell -ExecutionPolicy Bypass -File .\instalar-certificado.ps1 -ImpressaoDigital <40 hex>
# Desfazer:            powershell -ExecutionPolicy Bypass -File .\instalar-certificado.ps1 -Remover
# Remover um antigo:   powershell -ExecutionPolicy Bypass -File .\instalar-certificado.ps1 -RemoverImpressaoDigital <40 hex>
[CmdletBinding(DefaultParameterSetName = 'Instalar')]
param(
    [Parameter(ParameterSetName = 'Instalar', Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ImpressaoDigital,
    [Parameter(ParameterSetName = 'Instalar')][Parameter(ParameterSetName = 'Remover')]
    [string]$Certificado,
    [Parameter(ParameterSetName = 'Remover', Mandatory)][switch]$Remover,
    [Parameter(ParameterSetName = 'RemoverAntigo', Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$RemoverImpressaoDigital
)
$ErrorActionPreference = 'Stop'
# Default no corpo: no Windows PowerShell 5.1 com -File, $PSScriptRoot é vazio nos defaults do param().
if (-not $Certificado) { $Certificado = Join-Path $PSScriptRoot 'etiqueta-codesign.cer' }
function Remove-Trusted([string]$Thumbprint) {
    # Limpa também TrustedPublisher, usado por versões anteriores deste script.
    foreach ($name in @('Root', 'TrustedPublisher')) {
        $store = [Security.Cryptography.X509Certificates.X509Store]::new($name, 'LocalMachine')
        $store.Open('ReadWrite')
        try { $store.Certificates.Find('FindByThumbprint', $Thumbprint.ToUpperInvariant(), $false) | ForEach-Object { $store.Remove($_) } }
        finally { $store.Close() }
    }
    Write-Output "Certificado $Thumbprint removido desta maquina."
}
if ($PSCmdlet.ParameterSetName -eq 'RemoverAntigo') { Remove-Trusted $RemoverImpressaoDigital; return }

$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path -LiteralPath $Certificado).Path)
if ($Remover) { Remove-Trusted $cert.Thumbprint; return }

if ($cert.Thumbprint -ne $ImpressaoDigital.ToUpperInvariant()) {
    throw "Impressao digital do arquivo ($($cert.Thumbprint)) difere da informada. Nada foi instalado."
}
# Só um certificado autoassinado, sem poder de CA, restrito a assinatura de código.
$ekus = @($cert.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } |
    ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
$constraints = $cert.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] }
$usage = $cert.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension] }
if ($ekus.Count -ne 1 -or $ekus[0] -ne '1.3.6.1.5.5.7.3.3' -or -not $constraints -or $constraints.CertificateAuthority -or
    -not $usage -or $usage.KeyUsages -ne [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -or
    $cert.Issuer -ne $cert.Subject) {
    throw 'Arquivo recusado: nao e um certificado autoassinado restrito a assinatura de codigo (EKU unica 1.3.6.1.5.5.7.3.3, CA=false).'
}
Write-Output "Certificado: $($cert.Subject), valido ate $($cert.NotAfter.ToString('yyyy-MM-dd'))"
# Só Root: basta para o Windows validar a cadeia. TrustedPublisher também liberaria scripts/macros assinados sem aviso.
$store = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
$store.Open('ReadWrite')
try { $store.Add($cert) } finally { $store.Close() }
Write-Output 'Certificado confiado nesta maquina.'
