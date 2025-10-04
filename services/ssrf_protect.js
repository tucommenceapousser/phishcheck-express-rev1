const dns = require('dns').promises;
const net = require('net');

function isPrivateIp(ip) {
  // simple RFC1918 + local check
  if (!net.isIP(ip)) return false;
  const parts = ip.split('.').map(Number);
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (ip === '127.0.0.1' || ip === '::1') return true;
  return false;
}

async function protectUrlAgainstSSRFRisks(url) {
  const u = new URL(url);
  const hostname = u.hostname;
  // resolve
  let info;
  try {
    info = await dns.lookup(hostname, { all: true });
  } catch (e) {
    throw new Error('DNS lookup failed: ' + e.message);
  }
  if (!info || info.length === 0) throw new Error('Could not resolve hostname');
  for (const r of info) {
    if (isPrivateIp(r.address)) throw new Error('Resolved to private IP (SSRFRisk)');
  }
  return true;
}

module.exports = { protectUrlAgainstSSRFRisks };
