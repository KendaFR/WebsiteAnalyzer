'use strict';

// ─── Proxies CORS gratuits ────────────────────────────────────────────────────
const CORS_PROXIES = [
  url => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
  url => `https://corsproxy.io/?${encodeURIComponent(url)}`,
];

async function fetchViaProxy(url, timeoutMs = 10000) {
  for (const proxyFn of CORS_PROXIES) {
    try {
      const ctrl = new AbortController();
      const tid = setTimeout(() => ctrl.abort(), timeoutMs);
      const res = await fetch(proxyFn(url), { signal: ctrl.signal });
      clearTimeout(tid);
      if (res.ok) {
        const text = await res.text();
        if (text && text.length > 50) return { text, headers: res.headers };
      }
    } catch (_) {}
  }
  throw new Error('Proxies indisponibles pour : ' + url);
}

async function fetchText(url, timeoutMs = 8000) {
  try { return (await fetchViaProxy(url, timeoutMs)).text; }
  catch (_) { return ''; }
}

async function headCheck(url, timeoutMs = 6000) {
  for (const proxyFn of CORS_PROXIES) {
    try {
      const ctrl = new AbortController();
      const tid = setTimeout(() => ctrl.abort(), timeoutMs);
      const res = await fetch(proxyFn(url), { signal: ctrl.signal });
      clearTimeout(tid);
      return res.ok;
    } catch (_) {}
  }
  return false;
}

// ─── UI helpers ───────────────────────────────────────────────────────────────
function setStatus(msg) {
  document.getElementById('statusText').textContent = msg;
  document.getElementById('statusBar').classList.add('active');
}
function hideStatus() { document.getElementById('statusBar').classList.remove('active'); }
function showError(msg) {
  const e = document.getElementById('errorBox');
  e.innerHTML = msg;
  e.classList.add('visible');
}
function hideError() { document.getElementById('errorBox').classList.remove('visible'); }
function setDot(id, type) {
  const d = document.getElementById(id);
  if (d) d.className = 'dot dot-' + type;
}
function esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ─── Entrée principale ────────────────────────────────────────────────────────
window.analyze = async function () {
  const raw = document.getElementById('urlInput').value.trim();
  if (!raw) return;

  let url = raw;
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  let domain, hostname, protocol;
  try {
    const u = new URL(url);
    hostname = u.hostname;
    domain = hostname.replace(/^www\./, '');
    protocol = u.protocol;
  } catch (_) {
    showError('URL invalide. Exemple : <code>amazon.fr</code>');
    return;
  }

  document.getElementById('results').classList.remove('visible');
  document.getElementById('analyzeBtn').disabled = true;
  hideError();

  setStatus('Lancement de l\'analyse complète…');

  const [
    whoisRes,
    pageRes,
    tpRes,
    secRes,
    popRes,
  ] = await Promise.allSettled([
    fetchWhois(domain),
    fetchPage(url),
    fetchTrustpilot(domain),
    checkSecurity(url, domain, protocol),
    checkPopularity(domain),
  ]);

  setStatus('Analyse des résultats…');

  const whois      = whoisRes.status === 'fulfilled' ? whoisRes.value      : {};
  const page       = pageRes.status  === 'fulfilled' ? pageRes.value       : { html: '', headers: {} };
  const tp         = tpRes.status    === 'fulfilled' ? tpRes.value         : { found: false };
  const sec        = secRes.status   === 'fulfilled' ? secRes.value        : {};
  const popularity = popRes.status   === 'fulfilled' ? popRes.value        : {};

  const meta   = parseMeta(page.html);
  const legal  = parseLegal(page.html, url);
  const social = parseSocial(page.html);
  const tech   = parseTech(page.html);

  hideStatus();
  render({ whois, tp, meta, legal, sec, popularity, social, tech, domain, url });
};

// ─── WHOIS / RDAP ─────────────────────────────────────────────────────────────
async function fetchWhois(domain) {
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 8000);
    const res = await fetch(`https://rdap.org/domain/${domain}`, { signal: ctrl.signal });
    if (!res.ok) throw new Error('rdap ' + res.status);
    const data = await res.json();
    let created = null, updated = null, expires = null, registrar = null;
    for (const ev of (data.events || [])) {
      if (ev.eventAction === 'registration') created = ev.eventDate;
      if (ev.eventAction === 'last changed')  updated = ev.eventDate;
      if (ev.eventAction === 'expiration')    expires = ev.eventDate;
    }
    for (const ent of (data.entities || [])) {
      if (ent.roles?.includes('registrar')) {
        const fn = ent.vcardArray?.[1]?.find(v => v[0] === 'fn');
        registrar = fn ? fn[3] : (ent.handle || null);
      }
    }
    return { created, updated, expires, registrar };
  } catch (_) {
    const html = await fetchText(`https://who.is/whois/${domain}`, 8000);
    const cm = html.match(/Creation Date[:\s]+([^\n<]+)/i) || html.match(/Created[:\s]+([^\n<]+)/i);
    const rm = html.match(/Registrar[:\s]+([^\n<]{3,60})/i);
    return { created: cm ? cm[1].trim() : null, registrar: rm ? rm[1].trim() : null, updated: null, expires: null };
  }
}

// ─── Page principale ──────────────────────────────────────────────────────────
async function fetchPage(url) {
  try {
    const result = await fetchViaProxy(url, 12000);
    return { html: result.text, headers: result.headers };
  } catch (_) { return { html: '', headers: {} }; }
}

// ─── Trustpilot ───────────────────────────────────────────────────────────────
async function fetchTrustpilot(domain) {
  const tpUrl = `https://www.trustpilot.com/review/${domain}`;
  const html = await fetchText(tpUrl, 10000);
  if (!html) return { found: false, score: null, reviews: null, category: null, url: tpUrl };

  const scoreMatch = html.match(/"ratingValue"\s*:\s*([\d.]+)/) ||
                     html.match(/TrustScore[^>]*>([\d.,]+)/i) ||
                     html.match(/"aggregateRating"[^}]*"ratingValue"\s*:\s*"?([\d.]+)"?/);
  const score = scoreMatch ? parseFloat(scoreMatch[1].replace(',', '.')) : null;

  const reviewMatch = html.match(/"reviewCount"\s*:\s*(\d+)/) ||
                      html.match(/"(\d[\d,\s]+)"\s*reviews?/i);
  const reviews = reviewMatch ? parseInt(reviewMatch[1].replace(/[\s,]/g, '')) : null;

  let category = null;
  if (score !== null) {
    if (score >= 4.5) category = 'Excellent';
    else if (score >= 4.0) category = 'Bien';
    else if (score >= 3.5) category = 'Moyen';
    else if (score >= 2.0) category = 'Mauvais';
    else category = 'Très mauvais';
  }
  return { found: score !== null, score, reviews, category, url: tpUrl };
}

// ─── Sécurité ─────────────────────────────────────────────────────────────────
async function checkSecurity(url, domain, protocol) {
  const isHttps = protocol === 'https:';
  const base = `https://${domain}`;
  const [hasRobots, hasSitemap] = await Promise.all([
    headCheck(`${base}/robots.txt`),
    headCheck(`${base}/sitemap.xml`).then(r => r || headCheck(`${base}/sitemap_index.xml`)),
  ]);
  return { isHttps, hasRobots, hasSitemap };
}

// ─── Popularité ───────────────────────────────────────────────────────────────
async function checkPopularity(domain) {
  const results = {};

  // Sites majeurs connus — liste étendue
  const knownMajors = [
    'google.com','youtube.com','facebook.com','twitter.com','instagram.com',
    'linkedin.com','github.com','amazon.com','amazon.fr','wikipedia.org',
    'reddit.com','netflix.com','apple.com','microsoft.com','openai.com',
    'anthropic.com','x.com','tiktok.com','whatsapp.com','ebay.fr','ebay.com',
    'leboncoin.fr','fnac.com','cdiscount.com','paypal.com','airbnb.com',
    'booking.com','tripadvisor.com','stackoverflow.com','twitch.tv','discord.com',
    'spotify.com','figma.com','notion.so','vercel.com','cloudflare.com',
    'gitlab.com','npmjs.com','pypi.org','hub.docker.com','mozilla.org',
    'wordpress.com','shopify.com','stripe.com','salesforce.com','adobe.com',
  ];
  results.isKnownMajor = knownMajors.includes(domain);

  // Tranco rank (top 1M sites)
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 7000);
    const res = await fetch(`https://tranco-list.eu/api/ranks/domain/${domain}`, { signal: ctrl.signal });
    if (res.ok) {
      const data = await res.json();
      const ranks = data?.ranks || [];
      results.trancoRank = ranks.length > 0 ? ranks[0].rank : null;
    } else { results.trancoRank = null; }
  } catch (_) { results.trancoRank = null; }

  // Wikipedia
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 6000);
    const domainBase = domain.split('.')[0].toLowerCase();
    const res = await fetch(
      `https://fr.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(domainBase)}&format=json&origin=*&srlimit=5`,
      { signal: ctrl.signal }
    );
    if (res.ok) {
      const data = await res.json();
      const hits = data?.query?.search || [];
      results.wikipedia = hits.some(r =>
        r.title.toLowerCase().includes(domainBase) || (r.snippet||'').toLowerCase().includes(domainBase)
      );
      results.wikipediaTitle = results.wikipedia ? hits[0]?.title : null;
    }
  } catch (_) { results.wikipedia = false; }

  // Open PageRank (gratuit, sans clé)
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 5000);
    const res = await fetch(
      `https://openpagerank.com/api/v1.0/getPageRank?domains[]=${encodeURIComponent(domain)}`,
      { headers: { 'API-OPR': '0kok0k0kok0kok0k' }, signal: ctrl.signal }
    );
    if (res.ok) {
      const data = await res.json();
      results.pageRank = data?.response?.[0]?.page_rank_decimal ?? null;
    }
  } catch (_) { results.pageRank = null; }

  return results;
}

// ─── Parsing meta ─────────────────────────────────────────────────────────────
function parseMeta(html) {
  if (!html) return {};
  const get = pat => { const m = html.match(pat); return m ? (m[1]?.trim().substring(0,300)||null) : null; };
  return {
    title:       get(/<title[^>]*>([^<]{1,200})<\/title>/i),
    description: get(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']{1,300})/i) ||
                 get(/<meta[^>]+content=["']([^"']{1,300})["'][^>]+name=["']description["']/i),
    ogTitle:     get(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']{1,200})/i),
    ogDesc:      get(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']{1,300})/i),
    ogImage:     get(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']{1,300})/i),
    ogSiteName:  get(/<meta[^>]+property=["']og:site_name["'][^>]+content=["']([^"']{1,200})/i),
    twitterCard: get(/<meta[^>]+name=["']twitter:card["'][^>]+content=["']([^"']{1,100})/i),
    robots:      get(/<meta[^>]+name=["']robots["'][^>]+content=["']([^"']{1,100})/i),
    canonical:   get(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']{1,300})/i),
    charset:     get(/<meta[^>]+charset=["']?([A-Za-z0-9-]{1,30})/i),
    viewport:    /<meta[^>]+name=["']viewport["']/i.test(html),
    hreflang:    /<link[^>]+hreflang=/i.test(html),
    schema:      /<script[^>]+type=["']application\/ld\+json["']/i.test(html),
    favicon:     /<link[^>]+rel=["'][^"']*icon[^"']*["']/i.test(html),
    ampLink:     /<link[^>]+rel=["']amphtml["']/i.test(html),
  };
}

// ─── Parsing légal ────────────────────────────────────────────────────────────
function parseLegal(html, baseUrl) {
  if (!html) return { mentionsLegales:false, cgu:false, cgv:false, confidentialite:false, cookies:false, contact:false, links:[] };
  const lower = html.toLowerCase();
  const check = kws => kws.some(k => lower.includes(k));
  const mentionsLegales = check(['mentions légales','mentions-legales','/legal-notice','/legal','/mentions']);
  const cgu  = check(['conditions générales d\'utilisation','conditions-generales','cgu','/tos','/terms']);
  const cgv  = check(['conditions générales de vente','conditions de vente','cgv','/terms-of-sale']);
  const confidentialite = check(['politique de confidentialité','confidentialité','données personnelles','rgpd','gdpr','/privacy','/confidentialite']);
  const cookies = check(['politique de cookies','cookie policy','gestion des cookies','/cookies','cookie notice']);
  const contact = check(['/contact','contactez-nous','nous contacter','mailto:','contact us','contact@']);

  const legalLinks = [];
  const linkRe = /href=["']([^"'#]{5,300})["'][^>]*>([^<]{3,80})</gi;
  let m;
  const kws = ['legal','mention','cgu','cgv','condition','privacy','confidential','cookie','contact','rgpd','gdpr','terms'];
  while ((m = linkRe.exec(html)) !== null) {
    const href = m[1], text = m[2].trim();
    if (kws.some(k => (href+' '+text).toLowerCase().includes(k))) {
      let fullUrl = href;
      if (href.startsWith('/')) { try { fullUrl = new URL(href, baseUrl).href; } catch (_) {} }
      if (!legalLinks.find(l => l.href === fullUrl)) legalLinks.push({ href: fullUrl, text });
    }
    if (legalLinks.length >= 10) break;
  }
  return { mentionsLegales, cgu, cgv, confidentialite, cookies, contact, links: legalLinks };
}

// ─── Réseaux sociaux ──────────────────────────────────────────────────────────
function parseSocial(html) {
  if (!html) return {};
  return {
    twitter:   /twitter\.com\/(?!share|intent)[a-z0-9_]+/i.test(html) || /["']https?:\/\/x\.com\/[a-z]/i.test(html),
    linkedin:  /linkedin\.com\/(company|in)\//i.test(html),
    facebook:  /facebook\.com\/[a-z0-9.]{3,}/i.test(html),
    instagram: /instagram\.com\/[a-z0-9._]+/i.test(html),
    youtube:   /youtube\.com\/(channel|c|user|@)/i.test(html),
    github:    /github\.com\/[a-z0-9-]{2,}/i.test(html),
  };
}

// ─── Tech stack ───────────────────────────────────────────────────────────────
function parseTech(html) {
  if (!html) return {};
  return {
    hasGoogleAnalytics: /google.*analytics|gtag\(|ga\('send'|googletagmanager/i.test(html),
    hasCookieBanner:    /cookiebot|axeptio|tarteaucitron|cookieconsent|onetrust|cookiepro/i.test(html),
    hasLiveChat:        /intercom|zendesk|crisp\.chat|tawk\.to|drift\.com|livechat/i.test(html),
    hasPayment:         /stripe|paypal|mollie|braintree|checkout\.com/i.test(html),
    hasCDN:             /cloudflare|fastly|akamai|cloudfront|jsdelivr/i.test(html),
  };
}

// ─── Score ────────────────────────────────────────────────────────────────────
function computeScore({ whois, tp, meta, legal, sec, popularity, social, tech }) {
  let score = 0;
  const details = {};

  // POPULARITÉ (25 pts)
  let popScore = 0;
  if (popularity.isKnownMajor) {
    popScore = 25;
  } else if (popularity.trancoRank !== null && popularity.trancoRank !== undefined) {
    const r = popularity.trancoRank;
    if      (r <= 1000)   popScore = 25;
    else if (r <= 10000)  popScore = 22;
    else if (r <= 50000)  popScore = 18;
    else if (r <= 100000) popScore = 14;
    else if (r <= 500000) popScore = 9;
    else                   popScore = 5;
  }
  if (popularity.wikipedia && !popularity.isKnownMajor) popScore = Math.min(25, popScore + 6);
  if (popularity.pageRank  && popularity.pageRank >= 5)  popScore = Math.min(25, popScore + 3);
  score += popScore;
  details.popularity = popScore;

  // TRUSTPILOT (20 pts)
  let tpScore = tp.found && tp.score ? Math.round((tp.score / 5) * 20) : 3;
  score += tpScore;
  details.trustpilot = tpScore;

  // ÂGE DOMAINE (20 pts)
  const ageYears = computeAge(whois.created);
  let ageScore = 3;
  if (ageYears !== null) {
    if      (ageYears >= 15) ageScore = 20;
    else if (ageYears >= 10) ageScore = 18;
    else if (ageYears >= 5)  ageScore = 14;
    else if (ageYears >= 3)  ageScore = 10;
    else if (ageYears >= 1)  ageScore = 5;
    else                      ageScore = 0;
  }
  score += ageScore;
  details.age = ageScore;

  // SÉCURITÉ (15 pts)
  let secScore = 0;
  if (sec.isHttps)    secScore += 8;
  if (sec.hasRobots)  secScore += 4;
  if (sec.hasSitemap) secScore += 3;
  score += secScore;
  details.security = secScore;

  // MENTIONS LÉGALES (12 pts)
  const legalItems = ['mentionsLegales','cgu','cgv','confidentialite','cookies','contact'];
  const legalCount = legalItems.filter(k => legal[k]).length;
  const legalScore = Math.round((legalCount / legalItems.length) * 12);
  score += legalScore;
  details.legal = legalScore;

  // RÉSEAUX SOCIAUX (5 pts)
  const socialScore = Math.min(5, Object.values(social).filter(Boolean).length);
  score += socialScore;
  details.social = socialScore;

  // SEO / META (3 pts)
  const metaOk = [meta.title, meta.description, meta.ogTitle, meta.canonical, meta.viewport].filter(Boolean).length;
  const metaScore = Math.round((metaOk / 5) * 3);
  score += metaScore;
  details.meta = metaScore;

  return { total: Math.min(100, Math.max(0, score)), details };
}

function computeAge(dateStr) {
  if (!dateStr) return null;
  try {
    const d = new Date(dateStr);
    if (isNaN(d)) return null;
    return Math.max(0, (Date.now() - d.getTime()) / (1000*60*60*24*365.25));
  } catch (_) { return null; }
}

function formatAge(dateStr) {
  const y = computeAge(dateStr);
  if (y === null) return null;
  if (y < 1) { const m = Math.floor(y*12); return m<=1 ? 'moins d\'1 mois' : m+' mois'; }
  const yr = Math.floor(y);
  return yr + ' an' + (yr>1?'s':'');
}

function scoreLabel(s) {
  if (s >= 85) return 'Très fiable';
  if (s >= 70) return 'Fiable';
  if (s >= 50) return 'Correct';
  if (s >= 35) return 'Prudence';
  return 'Suspect';
}
function scoreColor(s) {
  if (s >= 70) return '#1D9E75';
  if (s >= 45) return '#BA7517';
  return '#E24B4A';
}
function dotType(val, good, warn) {
  return val >= good ? 'ok' : val >= warn ? 'warn' : 'bad';
}

// ─── Rendu ────────────────────────────────────────────────────────────────────
function render({ whois, tp, meta, legal, sec, popularity, social, tech, domain, url }) {
  document.getElementById('results').classList.add('visible');
  document.getElementById('analyzeBtn').disabled = false;

  const { total, details } = computeScore({ whois, tp, meta, legal, sec, popularity, social, tech });
  const ageYears = computeAge(whois.created);
  const ageText  = formatAge(whois.created);
  const legalItems = ['mentionsLegales','cgu','cgv','confidentialite','cookies','contact'];
  const legalFound = legalItems.filter(k => legal[k]).length;
  const secCount = [sec.isHttps, sec.hasRobots, sec.hasSitemap].filter(Boolean).length;

  // Score global
  document.getElementById('globalScore').textContent = total;
  document.getElementById('globalScore').style.color = scoreColor(total);
  document.getElementById('globalLabel').textContent = scoreLabel(total);

  // Mini cards
  if (tp.found && tp.score) {
    document.getElementById('tpScore').textContent = tp.score.toFixed(1)+' / 5';
    document.getElementById('tpReviews').textContent = tp.reviews ? tp.reviews.toLocaleString('fr-FR')+' avis' : (tp.category||'—');
    const bar = document.getElementById('tpBar');
    bar.style.width = Math.round(tp.score/5*100)+'%';
    bar.style.background = tp.score>=4?'var(--green)':tp.score>=3?'var(--amber)':'var(--red)';
  } else {
    document.getElementById('tpScore').textContent = 'N/A';
    document.getElementById('tpReviews').textContent = 'Non trouvé';
  }

  document.getElementById('domainAge').textContent = ageText || '?';
  document.getElementById('domainDate').textContent = whois.created
    ? 'Créé : '+new Date(whois.created).toLocaleDateString('fr-FR',{year:'numeric',month:'short',day:'numeric'})
    : 'WHOIS indisponible';

  document.getElementById('legalScore').textContent = legalFound+'/'+legalItems.length;
  document.getElementById('legalSub').textContent = 'éléments trouvés';

  // Popularity card
  document.getElementById('popValue').textContent = popularityText(popularity);
  document.getElementById('popSub').textContent   = popularitySub(popularity);

  // Security card
  document.getElementById('secValue').textContent = secCount+'/3';
  document.getElementById('secSub').textContent   = sec.isHttps ? 'HTTPS actif' : '⚠ Pas de HTTPS';

  // Score breakdown
  renderScoreBar(details);

  // Trustpilot
  setDot('tpDot', tp.found&&tp.score ? dotType(tp.score,4,3) : 'warn');
  const tpEl = document.getElementById('tpDetail');
  if (tp.found && tp.score) {
    tpEl.innerHTML = `Note <strong>${tp.score.toFixed(1)}/5</strong> (${esc(tp.category||'')})${tp.reviews?' — '+tp.reviews.toLocaleString('fr-FR')+' avis':''}.
      <a href="${esc(tp.url)}" target="_blank" rel="noopener" style="color:var(--blue);font-size:12px;margin-left:6px;">→ Voir sur Trustpilot</a>`;
  } else {
    tpEl.innerHTML = `Aucune fiche Trustpilot détectée pour <em>${esc(domain)}</em>.
      <a href="${esc(tp.url)}" target="_blank" rel="noopener" style="color:var(--blue);font-size:12px;margin-left:4px;">Vérifier manuellement →</a>`;
  }

  // Domaine
  setDot('domainDot', ageYears===null?'warn':dotType(ageYears,5,2));
  let domHtml = '';
  if (whois.created) {
    domHtml += `Enregistré le <strong>${new Date(whois.created).toLocaleDateString('fr-FR',{year:'numeric',month:'long',day:'numeric'})}</strong> — ancienneté : <strong>${ageText}</strong>. `;
    if      (ageYears < 1) domHtml += '<span style="color:var(--red-text)">Domaine très récent, soyez vigilant.</span>';
    else if (ageYears < 2) domHtml += '<span style="color:var(--amber-text)">Domaine récent.</span>';
    else                    domHtml += '<span style="color:var(--green-text)">Ancienneté satisfaisante.</span>';
  } else {
    domHtml = 'Impossible de récupérer la date de création (domaine protégé ou WHOIS indisponible).';
  }
  if (whois.registrar) domHtml += `<br><small style="opacity:.65;">Registrar : ${esc(whois.registrar)}</small>`;
  if (whois.expires)   domHtml += `<br><small style="opacity:.65;">Expiration : ${new Date(whois.expires).toLocaleDateString('fr-FR',{year:'numeric',month:'short',day:'numeric'})}</small>`;
  document.getElementById('domainDetail').innerHTML = domHtml;

  // Popularité
  const popRank = popularity.trancoRank;
  setDot('popDot',
    popularity.isKnownMajor || (popRank && popRank<=10000) ? 'ok' :
    (popRank && popRank<=200000) || popularity.wikipedia   ? 'warn' : 'bad'
  );
  document.getElementById('popDetail').innerHTML = buildPopularityHtml(popularity, domain);

  // Sécurité
  setDot('secDot', dotType(secCount,3,2));
  renderSecurityGrid(sec, tech);

  // Réseaux sociaux
  const socialCount = Object.values(social).filter(Boolean).length;
  setDot('socialDot', socialCount>=3?'ok':socialCount>=1?'warn':'bad');
  renderSocialGrid(social);

  // Meta
  const metaOk = [meta.title,meta.description,meta.ogTitle,meta.canonical,meta.viewport].filter(Boolean).length;
  setDot('metaDot', dotType(metaOk,4,2));
  renderMetaTags(meta);

  // Légal
  setDot('legalDot', dotType(legalFound,5,3));
  renderLegalGrid(legal);
}

// ─── Score breakdown ──────────────────────────────────────────────────────────
function renderScoreBar(details) {
  const cats = [
    { label:'Popularité',       val:details.popularity, max:25, color:'#7F77DD' },
    { label:'Trustpilot',       val:details.trustpilot, max:20, color:'#1D9E75' },
    { label:'Âge domaine',      val:details.age,        max:20, color:'#378ADD' },
    { label:'Sécurité',         val:details.security,   max:15, color:'#BA7517' },
    { label:'Mentions légales', val:details.legal,      max:12, color:'#D4537E' },
    { label:'Réseaux sociaux',  val:details.social,     max:5,  color:'#5DCAA5' },
    { label:'SEO / Meta',       val:details.meta,       max:3,  color:'#888780' },
  ];
  document.getElementById('scoreBreakdown').innerHTML = cats.map(c => {
    const pct = Math.round((c.val/c.max)*100);
    return `<div style="display:flex;align-items:center;gap:10px;font-size:12px;">
      <span style="min-width:130px;color:var(--text-secondary);">${esc(c.label)}</span>
      <div style="flex:1;height:6px;background:var(--bg-tertiary);border-radius:3px;overflow:hidden;">
        <div style="height:100%;width:${pct}%;background:${c.color};border-radius:3px;transition:width .6s;"></div>
      </div>
      <span style="min-width:48px;text-align:right;color:var(--text-tertiary);font-family:'IBM Plex Mono',monospace;">${c.val}/${c.max}</span>
    </div>`;
  }).join('');
}

// ─── Popularité ───────────────────────────────────────────────────────────────
function popularityText(pop) {
  if (pop.isKnownMajor) return 'Top mondial';
  if (pop.trancoRank) {
    if (pop.trancoRank<=1000)   return 'Top 1 000';
    if (pop.trancoRank<=10000)  return 'Top 10 000';
    if (pop.trancoRank<=100000) return 'Top 100 k';
    if (pop.trancoRank<=500000) return 'Top 500 k';
    return 'Top 1 M';
  }
  return pop.wikipedia ? 'Connu' : 'Non classé';
}
function popularitySub(pop) {
  if (pop.isKnownMajor) return 'Site de référence';
  if (pop.trancoRank)   return 'Rang Tranco #'+pop.trancoRank.toLocaleString('fr-FR');
  if (pop.wikipedia)    return 'Présent sur Wikipedia';
  return 'Hors top 1 million';
}
function buildPopularityHtml(pop, domain) {
  let html = '';
  if (pop.isKnownMajor) html += `<span style="color:var(--green-text)"><strong>${esc(domain)}</strong> est un site de référence mondial reconnu.</span><br>`;
  if (pop.trancoRank) {
    const r = pop.trancoRank;
    html += `Classement <strong>Tranco</strong> : #${r.toLocaleString('fr-FR')} / 1 million de sites.`;
    html += r<=50000 ? ' <span style="color:var(--green-text)">Excellente notoriété.</span>'
          : r<=200000 ? ' <span style="color:var(--amber-text)">Notoriété correcte.</span>'
          : ' <span style="color:var(--amber-text)">Notoriété modérée.</span>';
    html += '<br>';
  } else {
    html += `<span style="color:var(--text-tertiary)">Domaine non classé dans le Top 1 million Tranco.</span><br>`;
  }
  if (pop.wikipedia) {
    html += `<span style="color:var(--green-text)">✓ Article Wikipédia</span>`;
    if (pop.wikipediaTitle) html += ` : <em>${esc(pop.wikipediaTitle)}</em>`;
    html += '.<br>';
  } else {
    html += `<span style="color:var(--text-tertiary)">✗ Pas d'article Wikipédia détecté.</span><br>`;
  }
  if (pop.pageRank !== null && pop.pageRank !== undefined) {
    html += `PageRank public : <strong>${pop.pageRank}/10</strong>.`;
  }
  return html || 'Données de popularité non disponibles.';
}

// ─── Sécurité grid ────────────────────────────────────────────────────────────
function renderSecurityGrid(sec, tech) {
  const items = [
    { label:'HTTPS',              val:sec.isHttps,              detail:sec.isHttps?'Chiffrement actif':'Connexion non sécurisée', important:true },
    { label:'robots.txt',         val:sec.hasRobots,            detail:sec.hasRobots?'Présent':'Absent' },
    { label:'sitemap.xml',        val:sec.hasSitemap,           detail:sec.hasSitemap?'Présent':'Absent' },
    { label:'Bandeau cookies',    val:tech.hasCookieBanner,     detail:tech.hasCookieBanner?'Détecté':'Non détecté' },
    { label:'Google Analytics',   val:tech.hasGoogleAnalytics,  detail:tech.hasGoogleAnalytics?'Présent':'Absent' },
    { label:'Paiement sécurisé',  val:tech.hasPayment,          detail:tech.hasPayment?'Stripe/PayPal/…':'Non détecté' },
    { label:'CDN',                val:tech.hasCDN,              detail:tech.hasCDN?'Cloudflare/CDN':'Non détecté' },
    { label:'Chat en direct',     val:tech.hasLiveChat,         detail:tech.hasLiveChat?'Détecté':'Non détecté' },
  ];
  document.getElementById('secGrid').innerHTML = items.map(item => `
    <div class="legal-item">
      <span>${esc(item.label)}</span>
      <span class="badge ${item.val?(item.important?'badge-ok':'badge-neutral-ok'):'badge-neutral'}">${item.val?'✓':'✗'} ${esc(item.detail)}</span>
    </div>`).join('');
}

// ─── Social grid ──────────────────────────────────────────────────────────────
function renderSocialGrid(social) {
  const items = [
    {key:'twitter',   label:'Twitter / X'},
    {key:'linkedin',  label:'LinkedIn'},
    {key:'facebook',  label:'Facebook'},
    {key:'instagram', label:'Instagram'},
    {key:'youtube',   label:'YouTube'},
    {key:'github',    label:'GitHub'},
  ];
  document.getElementById('socialGrid').innerHTML = items.map(item => `
    <div class="legal-item">
      <span>${esc(item.label)}</span>
      <span class="badge ${social[item.key]?'badge-ok':'badge-neutral'}">${social[item.key]?'✓ Lié':'✗ Absent'}</span>
    </div>`).join('');
}

// ─── Meta tags ────────────────────────────────────────────────────────────────
function renderMetaTags(meta) {
  const wrap = document.getElementById('tagsWrap');
  wrap.innerHTML = '';
  [
    {label:'title',val:meta.title},{label:'meta desc',val:meta.description},
    {label:'og:title',val:meta.ogTitle},{label:'og:image',val:meta.ogImage},
    {label:'twitter:card',val:meta.twitterCard},{label:'viewport',val:meta.viewport},
    {label:'canonical',val:meta.canonical},{label:'robots',val:meta.robots},
    {label:'schema.org',val:meta.schema},{label:'hreflang',val:meta.hreflang},
    {label:'charset',val:meta.charset},{label:'favicon',val:meta.favicon},
    {label:'AMP',val:meta.ampLink},
  ].forEach(t => {
    const ok = t.val && t.val !== false;
    const pill = document.createElement('span');
    pill.className = 'tag-pill '+(ok?'tag-ok':'tag-bad');
    if (ok && typeof t.val==='string') pill.title = t.val;
    pill.textContent = (ok?'✓ ':'✗ ')+t.label;
    wrap.appendChild(pill);
  });

  const table = document.getElementById('metaValues');
  table.innerHTML = [
    {key:'Title',val:meta.title},{key:'Description',val:meta.description},
    {key:'OG Title',val:meta.ogTitle},{key:'OG Desc',val:meta.ogDesc},
    {key:'Site name',val:meta.ogSiteName},{key:'Twitter Card',val:meta.twitterCard},
    {key:'Robots',val:meta.robots},{key:'Canonical',val:meta.canonical},{key:'Charset',val:meta.charset},
  ].filter(r=>r.val).map(r =>
    `<div class="meta-row"><span class="meta-key">${esc(r.key)}</span><span class="meta-val">${esc(r.val)}</span></div>`
  ).join('');
}

// ─── Légal grid ───────────────────────────────────────────────────────────────
function renderLegalGrid(legal) {
  const defs = [
    {key:'mentionsLegales',label:'Mentions légales'},
    {key:'cgu',label:'CGU'},{key:'cgv',label:'CGV'},
    {key:'confidentialite',label:'Confidentialité / RGPD'},
    {key:'cookies',label:'Politique cookies'},{key:'contact',label:'Contact'},
  ];
  document.getElementById('legalGrid').innerHTML = defs.map(item => `
    <div class="legal-item">
      <span>${esc(item.label)}</span>
      <span class="badge ${legal[item.key]?'badge-ok':'badge-bad'}">${legal[item.key]?'✓ Présent':'✗ Absent'}</span>
    </div>`).join('');

  const linksEl = document.getElementById('legalLinks');
  if (legal.links && legal.links.length) {
    linksEl.innerHTML = '<strong style="font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--text-tertiary);">Liens trouvés</strong><br>'+
      legal.links.map(l=>`<a href="${esc(l.href)}" target="_blank" rel="noopener" style="color:var(--blue);font-size:12px;display:inline-block;margin-top:4px;margin-right:12px;">${esc(l.text)}</a>`).join('');
  } else {
    linksEl.textContent = '';
  }
}

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('urlInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') analyze();
  });
});
