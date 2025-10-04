// routes/analyze.js
const express = require('express');
const router = express.Router();
const validator = require('validator');
const xss = require('xss');
const { body, validationResult } = require('express-validator');

const { protectUrlAgainstSSRFRisks } = require('../services/ssrf_protect');
const { extractFaviconAndHash } = require('../services/favicon');
const { heuristicsCheck } = require('../services/heuristics');
const { shodanSearch } = require('../services/shodan');
const { virustotalScan } = require('../services/virustotal');

/**
 * Validation & sanitization middleware:
 * - Vérifie que le champ 'url' existe, est une string et n'est pas trop long.
 * - Applique xss() pour supprimer tags/scripts éventuels.
 */
const urlValidation = [
  body('url')
    .exists().withMessage('Missing url')
    .bail()
    .isString().withMessage('URL must be a string')
    .bail()
    .isLength({ min: 3, max: 2000 }).withMessage('URL length invalid')
    .bail()
    .trim()
    .customSanitizer((v) => {
      // sanitize potential XSS payloads
      return xss(v);
    })
];

router.post('/', urlValidation, async (req, res) => {
  // check express-validator results
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // render error to UI (consistent with app behavior)
    return res.status(400).render('result', { error: errors.array().map(e => e.msg).join('; '), result: null });
  }

  // get sanitized value
  let { url } = req.body;
  if (!url) return res.status(400).render('result', { error: 'Missing url', result: null });

  // Normalize: add protocol if absent
  if (!/^https?:\/\//i.test(url)) {
    url = 'http://' + url;
  }

  // Final syntactic URL validation with validator.js
  if (!validator.isURL(url, { require_protocol: true })) {
    return res.status(400).render('result', { error: 'Invalid URL format', result: null });
  }

  // Optional: double sanitize the normalized URL (defense in depth)
  url = xss(url);

  // SSRF protection (resolves host and checks private ranges)
  try {
    await protectUrlAgainstSSRFRisks(url);
  } catch (e) {
    return res.render('result', { error: `SSRF protection: ${e.message}`, result: null });
  }

  const result = { target: url };

  // heuristics
  try {
    result.heuristics = heuristicsCheck(url);
  } catch (e) {
    result.heuristics = [];
    result.heuristics_error = e.message;
  }

  // favicon + hash
  try {
    const fav = await extractFaviconAndHash(url);
    result.favicon = fav;
    if (fav && fav.hash && process.env.SHODAN_API_KEY) {
      try {
        result.shodan = await shodanSearch(fav.hash);
      } catch (e) {
        result.shodan_error = e.message;
      }
    }
  } catch (e) {
    result.favicon_error = e.message;
  }

  // VirusTotal (best-effort)
  if (process.env.VT_API_KEY) {
    try {
      result.virustotal = await virustotalScan(url);
    } catch (e) {
      result.virustotal_error = e.message;
    }
  }

  // Google Safe Browsing could be added similarly (if key present)

  // Render result page (EJS will escape variables by default for safety)
  return res.render('result', { error: null, result });
});

module.exports = router;
