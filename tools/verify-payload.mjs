// Confere o pacote enviado pelo pipeline privado antes de publicá-lo e gera as notas da release.
// Uso: node tools/verify-payload.mjs <pasta-do-pacote> <tag> <arquivo-notas>
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import process from 'node:process';
import { URL } from 'node:url';
import { verifyUpdater } from './verify-updater.mjs';

const [dir, tag, notesFile] = process.argv.slice(2);
const repository = process.env.GITHUB_REPOSITORY;
const fail = (message) => { throw new Error(message); };
if (!dir || !notesFile || !/^v\d+\.\d+\.\d+$/.test(tag ?? '') || !repository) fail('Uso: verify-payload.mjs <pasta> <vX.Y.Z> <notas> (com GITHUB_REPOSITORY)');
const version = tag.slice(1);
const files = readdirSync(dir).sort();
const installer = files.find((name) => name.endsWith(`_${version}_x64-setup.exe`)) ?? fail(`Instalador ${version} ausente`);
const expected = [installer, `${installer}.sig`, 'SHA256SUMS', 'build-info.json', 'latest.json'].sort();
if (JSON.stringify(files) !== JSON.stringify(expected)) fail(`Arquivos inesperados: ${files.join(', ')}`);

const sha256 = (name) => createHash('sha256').update(readFileSync(join(dir, name))).digest('hex');
const sums = readFileSync(join(dir, 'SHA256SUMS'), 'utf8').trim().split('\n').map((line) => line.split(/\s+\*?/));
const listed = sums.map(([, name]) => name).sort();
if (JSON.stringify(listed) !== JSON.stringify(files.filter((name) => name !== 'SHA256SUMS'))) fail('SHA256SUMS não cobre exatamente o pacote');
for (const [hash, name] of sums) if (sha256(name) !== hash) fail(`SHA-256 divergente: ${name}`);

const signature = readFileSync(join(dir, `${installer}.sig`), 'utf8').trim();
const manifest = JSON.parse(readFileSync(join(dir, 'latest.json'), 'utf8'));
const platform = manifest.platforms?.['windows-x86_64'];
if (manifest.version !== version) fail(`latest.json declara ${manifest.version}`);
if (Number.isNaN(Date.parse(manifest.pub_date))) fail('pub_date inválido');
if (platform?.url !== `https://github.com/${repository}/releases/download/${tag}/${installer}`) fail(`URL inesperada: ${platform?.url}`);
if (platform.signature !== signature) fail('Assinatura do latest.json difere do .sig');
const pubkey = readFileSync(new URL('./updater.pub', import.meta.url), 'utf8');
const trusted = verifyUpdater(readFileSync(join(dir, installer)), signature, pubkey);
const signed = trusted.split('\t');
if (!signed.includes(`file:${installer}`) || !signed.includes(`version:${version}`)) fail(`Assinatura updater não se refere a ${installer} ${version}: ${trusted}`);

const info = JSON.parse(readFileSync(join(dir, 'build-info.json'), 'utf8'));
if (info.version !== version || info.installerSha256 !== sha256(installer)) fail('build-info.json inconsistente');
writeFileSync(notesFile, [
  `${manifest.notes}`,
  '',
  'Instalador Windows x64 por usuário. O aplicativo instalado atualiza-se sozinho a partir desta página; cada pacote é conferido pela assinatura do atualizador antes de ser instalado.',
  '',
  `- SHA-256 do instalador: \`${info.installerSha256}\``,
  `- Authenticode autoassinado, impressão digital \`${info.authenticode?.thumbprint ?? 'n/d'}\`. Para confiar nele numa máquina (opcional, administrador): \`powershell -ExecutionPolicy Bypass -File .\\instalar-certificado.ps1 -ImpressaoDigital ${info.authenticode?.thumbprint ?? '<impressão>'}\``,
  `- Commit de origem: \`${info.commit.slice(0, 12)}\``,
].join('\n') + '\n');
process.stdout.write(`Pacote ${tag} conferido: ${trusted}\n`);
