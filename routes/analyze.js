const express = require('express');
const router = express.Router();
const validator = require('validator');
const { protectUrlAgainstSSRFRisks } = require('../services/ssrf_protect');
const { extractFaviconAndHash } = require('../services/favicon');
const { heuristicsCheck } = require('../services/heuristics');
const { shodanSearch } = require('../services/shodan');
const { virustotalScan } = require('../services/virustotal');

router.post('/', async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).send('Missing url');

  // normalize
  if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
  if (!validator.isURL(url, { require_protocol: true })) {
    return res.status(400).send('Invalid URL');
  }

  // SSRF protection (resolves host and checks private ranges)
  try {
    await protectUrlAgainstSSRFRisks(url);
  } catch (e) {
    return res.render('result', { error: e.message, result: null });
  }

  const result = { target: url };

  // heuristics
  result.heuristics = heuristicsCheck(url);

  // favicon + hash
  try {
    const fav = await extractFaviconAndHash(url);
    result.favicon = fav;
    if (fav && fav.hash && process.env.SHODAN_API_KEY) {
      result.shodan = await shodanSearch(fav.hash);
    }
  } catch (e) {
    result.favicon_error = e.message;
  }

  // VirusTotal (non-blocking if key set, but we'll await small timeout)
  if (process.env.VT_API_KEY) {
    try {
      result.virustotal = await virustotalScan(url);
    } catch (e) {
      result.virustotal_error = e.message;
    }
  }

  res.render('result', { error: null, result });
});

module.exports = router;
