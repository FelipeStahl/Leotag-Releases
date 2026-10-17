# Etiqueta — distribuição

Repositório público usado só para distribuir o instalador do **Etiqueta** e o manifesto do atualizador automático. O código-fonte é privado. Este conteúdo é mantido pelo pipeline de release; alterações manuais são sobrescritas.

## Instalar

1. Baixe `Etiqueta_<versão>_x64-setup.exe` da [última release](../../releases/latest).
2. Execute o instalador. Ele instala apenas para o usuário atual e não pede administrador.
3. Na primeira instalação o Windows pode mostrar *"O Windows protegeu o computador"* (SmartScreen): clique em *Mais informações → Executar assim mesmo*. Isso acontece porque o certificado é autoassinado (gratuito) e não tem reputação.
4. Depois disso o aplicativo verifica atualizações sozinho (ao abrir, a cada ~6 horas e pelo botão *Verificar atualizações*). Antes de instalar, confere a assinatura do atualizador; pacote alterado é recusado. As atualizações não passam pelo aviso do SmartScreen.

## Certificado de assinatura (gratuito, autoassinado)

O instalador, o desinstalador e o executável são assinados com um certificado Authenticode **autoassinado**, com carimbo de tempo. Para o SmartScreen ele equivale a um arquivo sem assinatura; a utilidade dele é permitir conferir que o arquivo foi produzido pelo pipeline do Etiqueta e não foi alterado.

Opcional, por máquina e como administrador: confiar no certificado faz o Windows mostrar a assinatura como **válida** (Propriedades → Assinaturas digitais, `Get-AuthenticodeSignature`) e permite regras de AppLocker/WDAC por editor. Não remove o aviso do SmartScreen. Baixe `instalar-certificado.ps1` e `etiqueta-codesign.cer` deste repositório para a mesma pasta e execute, com a impressão digital copiada das notas da release:

```powershell
powershell -ExecutionPolicy Bypass -File .\instalar-certificado.ps1 -ImpressaoDigital <impressão digital>
```

O script recusa o arquivo se a impressão digital não bater ou se o certificado não for autoassinado e restrito só à assinatura de código (sem poder de autoridade certificadora), e o instala apenas em *Autoridades de Certificação Raiz Confiáveis*. Para desfazer:

```powershell
powershell -ExecutionPolicy Bypass -File .\instalar-certificado.ps1 -Remover
```

Se o certificado for trocado, remova o antigo com `-RemoverImpressaoDigital <impressão antiga>`; a troca é anunciada nas notas da release.

Em máquinas com o *Controle Inteligente de Aplicativos* (Smart App Control) do Windows 11 ativado, aplicativos sem assinatura de uma autoridade pública podem ser bloqueados (`Get-MpComputerStatus | Select-Object SmartAppControlState`).

## Conferir um download

```powershell
Get-FileHash .\Etiqueta_<versão>_x64-setup.exe -Algorithm SHA256   # compare com SHA256SUMS da release
Get-AuthenticodeSignature .\Etiqueta_<versão>_x64-setup.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
```

Sem confiar no certificado, `Status` aparece como `UnknownError` (raiz não confiável); confira então a impressão digital em `SignerCertificate`.
