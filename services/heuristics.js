function heuristicsCheck(url) {
  const u = new URL(url);
  const host = u.hostname;
  const checks = [];
  // IP host
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) checks.push('Host is an IP address');
  if (host.length > 30) checks.push('Long domain name');
  if ((host.match(/\-/g) || []).length >= 3) checks.push('Multiple hyphens');
  const suspicious = ['login', 'secure', 'account', 'update', 'verify', 'bank', 'paypal', 'appleid'];
  for (const w of suspicious) if (url.toLowerCase().includes(w)) checks.push('Contains suspicious word: ' + w);
  if (u.protocol !== 'https:') checks.push('No HTTPS');
  // path with many params
  if ((u.search.match(/&/g) || []).length > 3) checks.push('Many query parameters');
  return checks;
}

module.exports = { heuristicsCheck };
