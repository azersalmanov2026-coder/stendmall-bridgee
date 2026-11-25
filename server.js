// StendMall <-> PASHA Bank ECOMM certificate proxy
import https from 'node:https';
import http from 'node:http';
import fs from 'node:fs';
import crypto from 'node:crypto';

const SECRET = process.env.PROXY_SECRET;
const PORT = Number(process.env.PORT || 8443);
const DIR = process.env.CERT_DIR || (fs.existsSync('/etc/secrets/public_cert.pem') ? '/etc/secrets' : './certs');
const MERCHANT_HANDLER = 'https://ecomm.pashabank.az:18443/ecomm2/MerchantHandler';

if (!SECRET || SECRET.length < 32) {
  console.error('PROXY_SECRET (ən azı 32 simvol) təyin edilməlidir');
  process.exit(1);
}

const agent = new https.Agent({
  cert: fs.readFileSync(`${DIR}/public_cert.pem`),
  key: fs.readFileSync(`${DIR}/private_cert.pem`),
  passphrase: process.env.KEY_PASSWORD || undefined,
  ca: fs.readFileSync(`${DIR}/PSroot.pem`),
  minVersion: 'TLSv1.2',
});

function bank(params) {
  const body = new URLSearchParams(params).toString();
  return new Promise((resolve, reject) => {
    const req = https.request(
      MERCHANT_HANDLER,
      {
        method: 'POST',
        agent,
        timeout: 30000,
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          'content-length': Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve(data));
      }
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end(body);
  });
}

const parse = (raw) =>
  Object.fromEntries(
    raw
      .split(/\r?\n/)
      .map((l) => l.split(/:\s*/))
      .filter((p) => p.length >= 2)
      .map(([k, ...v]) => [k.trim(), v.join(':').trim()])
  );

const safeEq = (a, b) => {
  const x = Buffer.from(a || ''),
    y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

const ip = (v) => (/^[0-9a-fA-F:.]{3,45}$/.test(v || '') ? v : '127.0.0.1');

http
  .createServer(async (req, res) => {
    const send = (code, obj) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(obj));
    };

    if (req.method === 'GET' && req.url === '/health') {
      return send(200, { ok: true });
    }

    if (req.method !== 'POST' || !safeEq(req.headers['x-proxy-secret'], SECRET)) {
      return send(401, { error: 'unauthorized' });
    }

    let raw = '';
    for await (const c of req) {
      raw += c;
      if (raw.length > 10000) return send(413, {});
    }

    let b;
    try {
      b = JSON.parse(raw);
    } catch {
      return send(400, { error: 'bad json' });
    }

    try {
      if (req.url === '/start' || req.url === '/register-payment') {
        if (b.client_ip_addr && !b.clientIp) b.clientIp = b.client_ip_addr;
        if (typeof b.amount === 'number') b.amount = String(b.amount);
        if (!b.currency) b.currency = '944';
        if (!/^\d{1,12}$/.test(b.amount) || !/^\d{3}$/.test(b.currency)) {
          return send(400, { error: 'bad amount' });
        }
        const r = parse(
          await bank({
            command: 'v',
            amount: b.amount,
            currency: b.currency,
            client_ip_addr: ip(b.clientIp),
            description: String(b.description || '').slice(0, 125),
            language: b.language || 'az',
            msg_type: 'SMS',
          })
        );
        if (!r.TRANSACTION_ID) {
          console.error('start error:', r);
          return send(502, { error: 'bank' });
        }
        return send(200, {
          transId: r.TRANSACTION_ID,
          transactionId: r.TRANSACTION_ID,
          paymentUrl:
            'https://ecomm.pashabank.az:8463/ecomm2/ClientHandler?trans_id=' +
            encodeURIComponent(r.TRANSACTION_ID),
        });
      }

      if (req.url === '/status' || req.url === '/check-status') {
        if (b.trans_id && !b.transId) b.transId = b.trans_id;
        if (b.client_ip_addr && !b.clientIp) b.clientIp = b.client_ip_addr;
        if (!b.transId || String(b.transId).length > 100) return send(400, { error: 'bad id' });
        const r = parse(
          await bank({
            command: 'c',
            trans_id: b.transId,
            client_ip_addr: ip(b.clientIp),
          })
        );
        const card = r.CARD_NUMBER || '';
        return send(200, {
          result: r.RESULT || '',
          resultCode: r.RESULT_CODE || '',
          rrn: r.RRN || '',
          approvalCode: r.APPROVAL_CODE || '',
          cardLast4: card.replace(/\D/g, '').slice(-4),
        });
      }

      return send(404, {});
    } catch (e) {
      console.error(e);
      return send(502, { error: 'bank unreachable' });
    }
  })
  .listen(PORT, '0.0.0.0', () => console.log('PASHA proxy listening on port', PORT));
