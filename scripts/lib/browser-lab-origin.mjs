/** Ephemeral CA/leaf pair trusted only by the private browser test profile. */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { exec } from './browser-lab-driver.mjs';

export async function browserOrigin(directory) {
  const caPath = join(directory, 'ca.pem'), caKey = join(directory, 'ca.key');
  const certPath = join(directory, 'leaf.pem'), keyPath = join(directory, 'leaf.key');
  const csr = join(directory, 'leaf.csr');
  await exec('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=meshpn-ephemeral-browser-lab', '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', caKey, '-out', caPath]);
  await exec('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost', '-addext', 'basicConstraints=critical,CA:FALSE',
    '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment', '-addext', 'extendedKeyUsage=serverAuth',
    '-keyout', keyPath, '-out', csr]);
  await exec('openssl', ['x509', '-req', '-in', csr, '-CA', caPath, '-CAkey', caKey,
    '-set_serial', '2', '-days', '1', '-copy_extensions', 'copy', '-out', certPath]);
  return { caPath, originTls: { cert: await readFile(certPath), key: await readFile(keyPath) } };
}
