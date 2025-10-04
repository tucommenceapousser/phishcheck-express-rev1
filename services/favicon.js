const axios = require('axios');
const cheerio = require('cheerio');
const murmur = require('murmurhash3js');

const USER_AGENT = 'Mozilla/5.0 (compatible; PhishCheck-Node/1.0)';

async function fetchBytes(url, opts = {}) {
  const r = await axios.get(url, { responseType: 'arraybuffer', timeout: 8000, headers: { 'User-Agent': USER_AGENT } });
  return r.data;
}

async function extractFaviconAndHash(target) {
  const u = new URL(target);
  const base = `${u.protocol}//${u.hostname}` + (u.port ? `:${u.port}` : '');
  // try /favicon.ico
  try {
    const favUrl = `${base}/favicon.ico`;
    const bytes = await fetchBytes(favUrl);
    if (bytes && bytes.byteLength > 0) {
      const b64 = Buffer.from(bytes).toString('base64');
      const h = murmur.x86.hash32(b64).toString();
      return { found_at: favUrl, size: bytes.byteLength, hash: h };
    }
  } catch (e) {
    // ignore and try HTML
  }
  // fetch page and find <link rel>
  try {
    const r = await axios.get(target, { headers: { 'User-Agent': USER_AGENT }, timeout: 8000 });
    const $ = cheerio.load(r.data);
    const link = $('link[rel*=icon]').first();
    if (link && link.attr('href')) {
      let href = link.attr('href');
      if (href.startsWith('//')) href = u.protocol + href;
      else if (href.startsWith('/')) href = base + href;
      else if (!href.startsWith('http')) href = base + '/' + href;
      const bytes = await fetchBytes(href);
      const b64 = Buffer.from(bytes).toString('base64');
      const h = murmur.x86.hash32(b64).toString();
      return { found_at: href, size: bytes.byteLength, hash: h };
    }
  } catch (e) {
    // ignore
  }
  return null;
}

module.exports = { extractFaviconAndHash };
