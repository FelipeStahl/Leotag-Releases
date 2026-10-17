import { Buffer } from 'node:buffer';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

export function verifyUpdater(bytes, signature, publicKey) {
  const keyLines = Buffer.from(publicKey.trim(), 'base64').toString('utf8').trim().split(/\r?\n/);
  const lines = Buffer.from(signature.trim(), 'base64').toString('utf8').trim().split(/\r?\n/);
  if (keyLines.length !== 2 || lines.length !== 4 || !lines[2].startsWith('trusted comment: ')) throw new Error('Formato minisign inválido');
  const key = Buffer.from(keyLines[1], 'base64');
  const sig = Buffer.from(lines[1], 'base64');
  if (key.length !== 42 || sig.length !== 74 || !key.subarray(2, 10).equals(sig.subarray(2, 10))) throw new Error('Chave de assinatura diferente');
  const algorithm = sig.subarray(0, 2).toString('ascii');
  if (algorithm !== 'ED' && algorithm !== 'Ed') throw new Error('Algoritmo não suportado');
  const pk = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), key.subarray(10)]), format: 'der', type: 'spki' });
  const message = algorithm === 'ED' ? createHash('blake2b512').update(bytes).digest() : bytes;
  if (!verify(null, message, pk, sig.subarray(10))) throw new Error('Assinatura do pacote inválida');
  const trustedComment = lines[2].slice('trusted comment: '.length);
  if (!verify(null, Buffer.concat([sig.subarray(10), Buffer.from(trustedComment)]), pk, Buffer.from(lines[3], 'base64'))) throw new Error('Comentário assinado inválido');
  return trustedComment;
}
const invokedDirectly = () => {
  try { return realpathSync(process.argv[1]).toLowerCase() === realpathSync(fileURLToPath(import.meta.url)).toLowerCase(); }
  catch { return false; }
};
if (invokedDirectly()) {
  if (process.argv.length < 5) throw new Error('Uso: node verify-updater.mjs <arquivo> <arquivo.sig> <chave-publica>');
  verifyUpdater(readFileSync(process.argv[2]), readFileSync(process.argv[3], 'utf8'), readFileSync(process.argv[4], 'utf8'));
  process.stdout.write('Assinatura updater verificada.\n');
}
