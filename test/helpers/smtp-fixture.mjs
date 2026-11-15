// A loopback-only SMTPS server for delivery tests, with a throwaway certificate generated in memory.
// Nothing here is a credential: the key exists only for the lifetime of the test process.
import tls from 'node:tls';
import { generateKeyPairSync, sign } from 'node:crypto';

const der = (tag, ...parts) => {
  const body = Buffer.concat(parts);
  const length =
    body.length < 128
      ? Buffer.from([body.length])
      : body.length < 256
        ? Buffer.from([0x81, body.length])
        : Buffer.from([0x82, body.length >> 8, body.length & 0xff]);
  return Buffer.concat([Buffer.from([tag]), length, body]);
};
const seq = (...parts) => der(0x30, ...parts);
const oid = (hex) => der(0x06, Buffer.from(hex, 'hex'));
const utc = (date) =>
  der(0x17, Buffer.from(date.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z', 'latin1'));

/** A self-signed ECDSA certificate for `localhost` and 127.0.0.1, valid for one day either side of now. */
export function selfSignedCertificate() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const algorithm = seq(oid('2a8648ce3d040302')); // ecdsa-with-SHA256
  const name = seq(der(0x31, seq(oid('550403'), der(0x0c, Buffer.from('localhost')))));
  const extensions = der(
    0xa3,
    seq(
      // subjectAltName: DNS localhost, IP 127.0.0.1
      seq(
        oid('551d11'),
        der(0x04, seq(der(0x82, Buffer.from('localhost')), der(0x87, Buffer.from([127, 0, 0, 1])))),
      ),
      // basicConstraints: CA, so the certificate can be its own trust anchor
      seq(oid('551d13'), der(0x01, Buffer.from([0xff])), der(0x04, seq(der(0x01, Buffer.from([0xff]))))),
    ),
  );
  const tbs = seq(
    der(0xa0, der(0x02, Buffer.from([2]))),
    der(0x02, Buffer.from([0x01, 0x23, 0x45, 0x67])),
    algorithm,
    name,
    seq(utc(new Date(Date.now() - 86_400_000)), utc(new Date(Date.now() + 86_400_000))),
    name,
    publicKey.export({ type: 'spki', format: 'der' }),
    extensions,
  );
  const signature = sign('sha256', tbs, privateKey);
  const certificate = seq(tbs, algorithm, der(0x03, Buffer.from([0]), signature));
  const pem = `-----BEGIN CERTIFICATE-----\n${certificate
    .toString('base64')
    .match(/.{1,64}/g)
    .join('\n')}\n-----END CERTIFICATE-----\n`;
  return { key: privateKey.export({ type: 'pkcs8', format: 'pem' }), cert: pem };
}

let trusted;
/** One certificate per test process, added to the default trust store so the real sender accepts it. */
export function trustedCertificate() {
  if (!trusted) {
    trusted = selfSignedCertificate();
    tls.setDefaultCACertificates([...tls.getCACertificates('default'), trusted.cert]);
  }
  return trusted;
}

/**
 * Starts a fake SMTPS server on 127.0.0.1. `behaviour` decides where the conversation goes wrong:
 * - `accept`: a normal server
 * - `drop-after-data`: takes the whole message, then closes without replying
 * - `drop-after-mail`: closes right after MAIL FROM
 * - `drop-after-ehlo`: closes after the first EHLO, before sign-in
 * - `auth-535` / `auth-454`: rejects the sign-in with that code
 * - `data-451` / `data-554`: answers the complete message with that code
 * - `untrusted`: presents a certificate the client does not trust
 */
export async function smtpsFixture(t, behaviour = 'accept') {
  const options = behaviour === 'untrusted' ? selfSignedCertificate() : trustedCertificate();
  const state = { messages: 0, commands: [], connections: 0 };
  const sockets = new Set();
  const server = tls.createServer(options, (socket) => {
    state.connections++;
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    let inData = false;
    let buffer = '';
    socket.write('220 localhost ESMTP fixture\r\n');
    socket.on('data', (chunk) => {
      buffer += chunk.toString('latin1');
      for (;;) {
        if (inData) {
          if (!buffer.includes('\r\n.\r\n')) return;
          state.messages++;
          inData = false;
          buffer = '';
          if (behaviour === 'drop-after-data') socket.destroy();
          else if (behaviour === 'data-451') socket.write('451 4.3.0 try again later\r\n');
          else if (behaviour === 'data-554') socket.write('554 5.7.1 message refused\r\n');
          else socket.write('250 2.0.0 queued\r\n');
          return;
        }
        const index = buffer.indexOf('\r\n');
        if (index < 0) return;
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 2);
        const verb = line.split(' ')[0].toUpperCase();
        state.commands.push(verb);
        if (verb === 'EHLO') {
          if (behaviour === 'drop-after-ehlo') return void socket.destroy();
          socket.write('250-localhost\r\n250 AUTH PLAIN LOGIN\r\n');
        } else if (verb === 'AUTH')
          socket.write(
            behaviour === 'auth-535'
              ? '535 5.7.8 Authentication credentials invalid\r\n'
              : behaviour === 'auth-454'
                ? '454 4.7.0 Temporary authentication failure\r\n'
                : '235 2.7.0 ok\r\n',
          );
        else if (verb === 'MAIL') {
          if (behaviour === 'drop-after-mail') return void socket.destroy();
          socket.write('250 2.1.0 ok\r\n');
        } else if (verb === 'RCPT') socket.write('250 2.1.5 ok\r\n');
        else if (verb === 'DATA') {
          socket.write('354 go ahead\r\n');
          inData = true;
        } else if (verb === 'QUIT') {
          socket.write('221 bye\r\n');
          socket.end();
        } else socket.write('250 ok\r\n');
      }
    });
  });
  server.on('tlsClientError', () => {});
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  return { state, url: `smtps://alerts:secret@localhost:${server.address().port}` };
}
