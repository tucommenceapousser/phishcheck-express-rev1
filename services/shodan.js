const axios = require('axios');

async function shodanSearch(hash) {
  const key = process.env.SHODAN_API_KEY;
  if (!key) throw new Error('SHODAN_API_KEY not set');
  const q = `http.favicon.hash:${hash}`;
  const url = `https://api.shodan.io/shodan/host/search?key=${key}&query=${encodeURIComponent(q)}`;
  const r = await axios.get(url, { timeout: 10000 });
  return r.data;
}

module.exports = { shodanSearch };
