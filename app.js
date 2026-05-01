'use strict';

// ─── Proxies CORS gratuits ────────────────────────────────────────────────────
// On essaie plusieurs proxies en cascade si l'un échoue
const CORS_PROXIES = [
  url => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
  url => `https://corsproxy.io/?${encodeURIComponent(url)}`,
  url => `https://cors-anywhere.herokuapp.com/${url}`,
];

async function fetchViaProxy(url, timeoutMs = 10000) {
  for (const proxyFn of CORS_PROXIES) {
    try {
      const proxyUrl = proxyFn(url);
      const ctrl = new AbortController();
      const tid = setTimeout(() => ctrl.abort(), timeoutMs);
      const res = await fetch(proxyUrl, { signal: ctrl.signal });
      clearTimeout(tid);
      if (res.ok) {
        const text = await res.text();
        if (text && text.length > 100) return text;
      }
    } catch (_) { /* essai suivant */ }
  }
  throw new Error('Tous les proxies ont échoué pour : ' + url);
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

  let domain, hostname;
  try {
    const u = new URL(url);
    hostname = u.hostname;
    domain = hostname.replace(/^www\./, '');
  } catch (_) {
    showError('URL invalide. Exemple : <code>amazon.fr</code>');
    return;
  }

  document.getElementById('results').classList.remove('visible');
  document.getElementById('analyzeBtn').disabled = true;
  hideError();

  try {
    // ── 1. WHOIS / âge domaine ────────────────────────────────────────────────
    setStatus('Récupération des informations WHOIS…');
    const whoisData = await fetchWhois(domain);

    // ── 2. Scraping page principale ───────────────────────────────────────────
    setStatus('Scraping de la page ' + domain + '…');
    const pageHtml = await fetchViaProxy(url).catch(() => '');

    // ── 3. Trustpilot ─────────────────────────────────────────────────────────
    setStatus('Recherche Trustpilot…');
    const tpData = await fetchTrustpilot(domain);

    // ── 4. Analyse ────────────────────────────────────────────────────────────
    setStatus('Analyse des résultats…');
    const metaData = parseMeta(pageHtml);
    const legalData = parseLegal(pageHtml, url);

    hideStatus();
    render({ whoisData, tpData, metaData, legalData, domain });

  } catch (err) {
    hideStatus();
    showError('Erreur : ' + esc(err.message));
    document.getElementById('analyzeBtn').disabled = false;
  }
};

// ─── WHOIS via rdap.org (100 % gratuit, pas de clé) ──────────────────────────
async function fetchWhois(domain) {
  // RDAP est le successeur officiel du WHOIS, API JSON publique
  const rdapUrl = `https://rdap.org/domain/${domain}`;
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 8000);
    const res = await fetch(rdapUrl, { signal: ctrl.signal });
    if (!res.ok) throw new Error('RDAP ' + res.status);
    const data = await res.json();

    // Chercher la date de création dans les events
    let created = null, updated = null, expires = null, registrar = null;
    if (data.events) {
      for (const ev of data.events) {
        if (ev.eventAction === 'registration') created = ev.eventDate;
        if (ev.eventAction === 'last changed') updated = ev.eventDate;
        if (ev.eventAction === 'expiration') expires = ev.eventDate;
      }
    }
    if (data.entities) {
      for (const ent of data.entities) {
        if (ent.roles && ent.roles.includes('registrar')) {
          registrar = ent.publicIds?.[0]?.identifier || ent.handle || null;
          if (ent.vcardArray) {
            const fn = ent.vcardArray[1]?.find(v => v[0] === 'fn');
            if (fn) registrar = fn[3];
          }
        }
      }
    }
    return { created, updated, expires, registrar, status: data.status, raw: null };
  } catch (_) {
    // Fallback : whois.domaintools via proxy
    try {
      const html = await fetchViaProxy(`https://who.is/whois/${domain}`, 8000);
      const createdMatch = html.match(/Creation Date[:\s]+([^\n<]+)/i) ||
                           html.match(/Registered On[:\s]+([^\n<]+)/i) ||
                           html.match(/Created[:\s]+([^\n<]+)/i);
      const registrarMatch = html.match(/Registrar[:\s]+([^\n<]{3,60})/i);
      return {
        created: createdMatch ? createdMatch[1].trim() : null,
        registrar: registrarMatch ? registrarMatch[1].trim() : null,
        updated: null, expires: null, status: null, raw: null
      };
    } catch (_2) {
      return { created: null, registrar: null, updated: null, expires: null, status: null };
    }
  }
}

// ─── Trustpilot scraping ──────────────────────────────────────────────────────
async function fetchTrustpilot(domain) {
  // TLD principal pour Trustpilot
  const tpUrl = `https://www.trustpilot.com/review/${domain}`;
  try {
    const html = await fetchViaProxy(tpUrl, 10000);

    // Score
    const scoreMatch = html.match(/"ratingValue"\s*:\s*([\d.]+)/) ||
                       html.match(/TrustScore[^>]*>([\d.,]+)\s*out of 5/i) ||
                       html.match(/"aggregateRating"[^}]*"ratingValue"\s*:\s*"?([\d.]+)"?/);
    const score = scoreMatch ? parseFloat(scoreMatch[1].replace(',', '.')) : null;

    // Nb avis
    const reviewMatch = html.match(/"reviewCount"\s*:\s*(\d+)/) ||
                        html.match(/(\d[\d\s,.]+)\s+avis/i) ||
                        html.match(/(\d[\d,]+)\s+reviews?/i);
    const reviews = reviewMatch ? parseInt(reviewMatch[1].replace(/[\s,]/g, '')) : null;

    // Étoiles / catégorie
    let category = null;
    if (score !== null) {
      if (score >= 4.5) category = 'Excellent';
      else if (score >= 4.0) category = 'Bien';
      else if (score >= 3.5) category = 'Moyen';
      else if (score >= 2.0) category = 'Mauvais';
      else category = 'Très mauvais';
    }

    return { found: score !== null, score, reviews, category, url: tpUrl };
  } catch (_) {
    return { found: false, score: null, reviews: null, category: null, url: tpUrl };
  }
}

// ─── Parsing balises meta ─────────────────────────────────────────────────────
function parseMeta(html) {
  if (!html) return {};
  const get = (pattern) => {
    const m = html.match(pattern);
    return m ? m[1]?.trim().substring(0, 200) || null : null;
  };

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
  };
}

// ─── Détection mentions légales ───────────────────────────────────────────────
function parseLegal(html, baseUrl) {
  if (!html) return { mentionsLegales: false, cgu: false, cgv: false, confidentialite: false, cookies: false, contact: false, links: [] };

  const lower = html.toLowerCase();

  const check = (keywords) => keywords.some(k => lower.includes(k));

  const mentionsLegales = check(['mentions légales', 'mentions-legales', 'mentions_legales', 'informations légales', 'legal notice', '/legal']);
  const cgu = check(['conditions générales d\'utilisation', 'conditions-generales-utilisation', 'cgu', 'terms of service', 'terms of use', '/tos', '/terms']);
  const cgv = check(['conditions générales de vente', 'conditions-generales-vente', 'cgv', 'conditions de vente', 'terms of sale']);
  const confidentialite = check(['politique de confidentialité', 'confidentialité', 'données personnelles', 'rgpd', 'gdpr', 'privacy policy', '/privacy', '/confidentialite']);
  const cookies = check(['politique de cookies', 'cookie policy', 'gestion des cookies', '/cookies', 'cookie notice']);
  const contact = check(['/contact', 'contactez-nous', 'nous contacter', 'mailto:', 'contact us', 'contact@']);

  // Extraire les liens légaux du footer (heuristique)
  const legalLinks = [];
  const linkRe = /href=["']([^"'#]{5,300})["'][^>]*>([^<]{3,80})</gi;
  let m;
  const legalKeywords = ['legal', 'mention', 'cgu', 'cgv', 'condition', 'privacy', 'confidential', 'cookie', 'contact', 'rgpd', 'gdpr'];
  while ((m = linkRe.exec(html)) !== null) {
    const href = m[1];
    const text = m[2].trim();
    const both = (href + ' ' + text).toLowerCase();
    if (legalKeywords.some(k => both.includes(k))) {
      let fullUrl = href;
      if (href.startsWith('/')) {
        try { fullUrl = new URL(href, baseUrl).href; } catch (_) {}
      }
      if (!legalLinks.find(l => l.href === fullUrl)) {
        legalLinks.push({ href: fullUrl, text });
      }
    }
    if (legalLinks.length >= 10) break;
  }

  return { mentionsLegales, cgu, cgv, confidentialite, cookies, contact, links: legalLinks };
}

// ─── Calcul score global ──────────────────────────────────────────────────────
function computeScore({ whoisData, tpData, metaData, legalData }) {
  let score = 0;

  // Trustpilot (30 pts)
  if (tpData.found && tpData.score) {
    score += Math.round((tpData.score / 5) * 30);
  } else {
    score += 5; // neutre si absent
  }

  // Âge domaine (25 pts)
  const ageYears = computeAge(whoisData.created);
  if (ageYears !== null) {
    if (ageYears >= 10) score += 25;
    else if (ageYears >= 5) score += 20;
    else if (ageYears >= 2) score += 12;
    else if (ageYears >= 1) score += 6;
    else score += 0;
  } else {
    score += 5;
  }

  // Mentions légales (30 pts)
  const legalItems = ['mentionsLegales','cgu','cgv','confidentialite','cookies','contact'];
  const legalCount = legalItems.filter(k => legalData[k]).length;
  score += Math.round((legalCount / legalItems.length) * 30);

  // Meta SEO (15 pts)
  const metaChecks = [!!metaData.title, !!metaData.description, !!metaData.ogTitle,
                      !!metaData.canonical, !!metaData.viewport, !!metaData.robots, !!metaData.schema];
  score += Math.round((metaChecks.filter(Boolean).length / metaChecks.length) * 15);

  return Math.min(100, Math.max(0, score));
}

function computeAge(dateStr) {
  if (!dateStr) return null;
  try {
    const d = new Date(dateStr);
    if (isNaN(d)) return null;
    const years = (Date.now() - d.getTime()) / (1000 * 60 * 60 * 24 * 365.25);
    return Math.max(0, years);
  } catch (_) { return null; }
}

function formatAge(dateStr) {
  const years = computeAge(dateStr);
  if (years === null) return null;
  if (years < 1) {
    const months = Math.floor(years * 12);
    return months <= 1 ? 'moins d\'1 mois' : months + ' mois';
  }
  const y = Math.floor(years);
  return y + ' an' + (y > 1 ? 's' : '');
}

function scoreLabel(s) {
  if (s >= 80) return 'Très fiable';
  if (s >= 65) return 'Fiable';
  if (s >= 45) return 'Correct';
  if (s >= 30) return 'Prudence';
  return 'Suspect';
}

// ─── Rendu ─────────────────────────────────────────────────────────────────────
function render({ whoisData, tpData, metaData, legalData, domain }) {
  document.getElementById('results').classList.add('visible');
  document.getElementById('analyzeBtn').disabled = false;

  const score = computeScore({ whoisData, tpData, metaData, legalData });

  // Score global
  const gEl = document.getElementById('globalScore');
  gEl.textContent = score;
  document.getElementById('globalLabel').textContent = scoreLabel(score);
  gEl.style.color = score >= 65 ? '#1D9E75' : score >= 40 ? '#BA7517' : '#E24B4A';

  // ── Trustpilot ──
  if (tpData.found && tpData.score) {
    document.getElementById('tpScore').textContent = tpData.score.toFixed(1) + ' / 5';
    document.getElementById('tpReviews').textContent = tpData.reviews
      ? tpData.reviews.toLocaleString('fr-FR') + ' avis'
      : tpData.category || '—';
    const pct = Math.round((tpData.score / 5) * 100);
    const bar = document.getElementById('tpBar');
    bar.style.width = pct + '%';
    bar.style.background = tpData.score >= 4 ? 'var(--green)' : tpData.score >= 3 ? 'var(--amber)' : 'var(--red)';
    setDot('tpDot', tpData.score >= 4 ? 'ok' : tpData.score >= 3 ? 'warn' : 'bad');

    let html = `Note <strong>${tpData.score.toFixed(1)}/5</strong> — ${esc(tpData.category || '')}.`;
    if (tpData.reviews) html += ` Basé sur ${tpData.reviews.toLocaleString('fr-FR')} avis.`;
    html += ` <a href="${esc(tpData.url)}" target="_blank" rel="noopener" style="color:var(--blue);font-size:12px;">→ Voir sur Trustpilot</a>`;
    document.getElementById('tpDetail').innerHTML = html;
  } else {
    document.getElementById('tpScore').textContent = 'N/A';
    document.getElementById('tpReviews').textContent = 'Non trouvé';
    document.getElementById('tpBar').style.width = '0%';
    setDot('tpDot', 'warn');
    document.getElementById('tpDetail').innerHTML =
      `Aucune fiche Trustpilot détectée pour <em>${esc(domain)}</em>. Cela peut indiquer un site récent ou peu connu. ` +
      `<a href="${esc(tpData.url)}" target="_blank" rel="noopener" style="color:var(--blue);font-size:12px;">Vérifier manuellement →</a>`;
  }

  // ── Domaine / WHOIS ──
  const ageText = formatAge(whoisData.created);
  const ageYears = computeAge(whoisData.created);

  if (ageText) {
    document.getElementById('domainAge').textContent = ageText;
    document.getElementById('domainDate').textContent = whoisData.created
      ? 'Créé : ' + new Date(whoisData.created).toLocaleDateString('fr-FR', { year:'numeric', month:'long', day:'numeric' })
      : '—';
    setDot('domainDot', ageYears >= 5 ? 'ok' : ageYears >= 2 ? 'warn' : 'bad');
  } else {
    document.getElementById('domainAge').textContent = '?';
    document.getElementById('domainDate').textContent = 'WHOIS non disponible';
    setDot('domainDot', 'warn');
  }

  let domHtml = '';
  if (whoisData.created) {
    const d = new Date(whoisData.created);
    domHtml += `Domaine enregistré le <strong>${d.toLocaleDateString('fr-FR', {year:'numeric',month:'long',day:'numeric'})}</strong> — ancienneté : <strong>${ageText}</strong>. `;
    if (ageYears < 1) domHtml += '<span style="color:var(--red-text)">Domaine très récent, soyez vigilant.</span>';
    else if (ageYears < 2) domHtml += '<span style="color:var(--amber-text)">Domaine récent, à vérifier.</span>';
    else domHtml += '<span style="color:var(--green-text)">Ancienneté satisfaisante.</span>';
  } else {
    domHtml = 'Impossible de récupérer la date de création via RDAP/WHOIS. Le domaine peut être protégé par la confidentialité.';
  }
  if (whoisData.registrar) domHtml += `<br><span style="font-size:12px;opacity:0.7;margin-top:4px;display:block;">Registrar : ${esc(whoisData.registrar)}</span>`;
  if (whoisData.expires) {
    const exp = new Date(whoisData.expires);
    domHtml += `<span style="font-size:12px;opacity:0.7;display:block;">Expire : ${exp.toLocaleDateString('fr-FR', {year:'numeric',month:'long',day:'numeric'})}</span>`;
  }
  document.getElementById('domainDetail').innerHTML = domHtml;

  // ── Balises meta ──
  const tagsWrap = document.getElementById('tagsWrap');
  tagsWrap.innerHTML = '';
  const tagDefs = [
    { label: 'title',        val: metaData.title },
    { label: 'meta desc',    val: metaData.description },
    { label: 'og:title',     val: metaData.ogTitle },
    { label: 'og:image',     val: metaData.ogImage },
    { label: 'twitter:card', val: metaData.twitterCard },
    { label: 'viewport',     val: metaData.viewport },
    { label: 'canonical',    val: metaData.canonical },
    { label: 'robots',       val: metaData.robots },
    { label: 'schema.org',   val: metaData.schema },
    { label: 'hreflang',     val: metaData.hreflang },
    { label: 'charset',      val: metaData.charset },
    { label: 'favicon',      val: metaData.favicon },
  ];
  tagDefs.forEach(t => {
    const present = t.val && t.val !== false;
    const pill = document.createElement('span');
    pill.className = 'tag-pill ' + (present ? 'tag-ok' : 'tag-bad');
    if (present && typeof t.val === 'string') pill.title = t.val;
    pill.textContent = (present ? '✓ ' : '✗ ') + t.label;
    tagsWrap.appendChild(pill);
  });

  const metaOkCount = tagDefs.filter(t => t.val && t.val !== false).length;
  setDot('metaDot', metaOkCount >= 8 ? 'ok' : metaOkCount >= 5 ? 'warn' : 'bad');

  // Tableau valeurs
  const metaTable = document.getElementById('metaTitle');
  metaTable.innerHTML = '';
  const metaRows = [
    { key: 'Title', val: metaData.title },
    { key: 'Description', val: metaData.description },
    { key: 'OG Title', val: metaData.ogTitle },
    { key: 'OG Description', val: metaData.ogDesc },
    { key: 'Site name', val: metaData.ogSiteName },
    { key: 'Twitter Card', val: metaData.twitterCard },
    { key: 'Robots', val: metaData.robots },
    { key: 'Canonical', val: metaData.canonical },
    { key: 'Charset', val: metaData.charset },
  ].filter(r => r.val);

  metaRows.forEach(r => {
    const row = document.createElement('div');
    row.className = 'meta-row';
    row.innerHTML = `<span class="meta-key">${esc(r.key)}</span><span class="meta-val">${esc(r.val)}</span>`;
    metaTable.appendChild(row);
  });

  // ── Mentions légales ──
  const legalDefs = [
    { key: 'mentionsLegales', label: 'Mentions légales' },
    { key: 'cgu',             label: 'CGU' },
    { key: 'cgv',             label: 'CGV' },
    { key: 'confidentialite', label: 'Confidentialité / RGPD' },
    { key: 'cookies',         label: 'Politique cookies' },
    { key: 'contact',         label: 'Contact' },
  ];
  const legalGrid = document.getElementById('legalGrid');
  legalGrid.innerHTML = '';
  let legalFound = 0;
  legalDefs.forEach(item => {
    const val = !!legalData[item.key];
    if (val) legalFound++;
    const div = document.createElement('div');
    div.className = 'legal-item';
    div.innerHTML = `<span>${esc(item.label)}</span><span class="badge ${val ? 'badge-ok' : 'badge-bad'}">${val ? '✓ Présent' : '✗ Absent'}</span>`;
    legalGrid.appendChild(div);
  });

  document.getElementById('legalScore').textContent = legalFound + '/' + legalDefs.length;
  document.getElementById('legalSub').textContent = 'éléments trouvés';
  setDot('legalDot', legalFound >= 5 ? 'ok' : legalFound >= 3 ? 'warn' : 'bad');

  // Liens légaux trouvés
  const legalLinksEl = document.getElementById('legalLinks');
  if (legalData.links && legalData.links.length > 0) {
    legalLinksEl.innerHTML = '<strong style="font-size:11px;color:var(--text-tertiary);text-transform:uppercase;letter-spacing:.08em;">Liens trouvés</strong><br>' +
      legalData.links.map(l =>
        `<a href="${esc(l.href)}" target="_blank" rel="noopener" style="color:var(--blue);display:inline-block;margin-top:4px;margin-right:12px;font-size:12px;">${esc(l.text)}</a>`
      ).join('');
  } else {
    legalLinksEl.textContent = '';
  }
}

// ─── Entrée clavier ───────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('urlInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') analyze();
  });
});
