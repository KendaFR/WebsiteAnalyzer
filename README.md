# Vérificateur de fiabilité — 100 % gratuit

Outil d'analyse de fiabilité d'un site web, sans clé API, sans inscription, sans coût.

## Lancement (ultra simple)

1. Extrayez le ZIP dans un dossier
2. Double-cliquez sur `index.html`
3. Collez une URL et cliquez "Analyser →"

C'est tout. Aucune installation, aucun serveur, aucun compte requis.

## Ce qui est analysé

| Critère            | Source                                | Gratuit |
|--------------------|---------------------------------------|---------|
| **Trustpilot**     | Scraping trustpilot.com via proxy CORS | ✅ |
| **Âge du domaine** | API RDAP publique (rdap.org)          | ✅ |
| **Balises meta**   | Scraping de la page cible             | ✅ |
| **Mentions légales** | Analyse du contenu de la page       | ✅ |

## APIs utilisées (toutes gratuites, sans clé)

- **rdap.org** — WHOIS/RDAP public (successeur officiel du WHOIS)
- **api.allorigins.win** — Proxy CORS gratuit (principal)
- **corsproxy.io** — Proxy CORS gratuit (fallback)

## Limitations connues

- Certains sites bloquent les proxies CORS → les données meta/légal peuvent être partielles
- Trustpilot peut bloquer le scraping → résultat "N/A" possible
- La confidentialité WHOIS (GDPR) peut masquer la date de création du domaine

## Structure

```
site-analyzer/
├── index.html   → Structure HTML
├── style.css    → Thème (light/dark automatique)
├── app.js       → Logique, APIs, parsing
└── README.md    → Ce fichier
```
