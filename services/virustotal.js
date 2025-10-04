const axios = require('axios');

async function virustotalScan(target) {
  const key = process.env.VT_API_KEY;
  if (!key) throw new Error('VT key not set');
  // Submit URL (v3)
  const submit = await axios.post('https://www.virustotal.com/api/v3/urls', `url=${encodeURIComponent(target)}`, { headers: { 'x-apikey': key, 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 });
  if (![200,201].includes(submit.status)) return { error: 'VT submit failed', status: submit.status };
  const analysisId = submit.data.data && submit.data.data.id;
  if (!analysisId) return submit.data;
  // try to fetch result (best-effort)
  const analysis = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, { headers: { 'x-apikey': key }, timeout: 10000 });
  return analysis.data;
}

module.exports = { virustotalScan };
