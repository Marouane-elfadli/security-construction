# SafetyMonitor v11 — Setup Sécurisé

## Ce qui a été ajouté (par chapitre du module)

### Ch.1 — Sécurisation réseau
- Flask bind sur `127.0.0.1` uniquement (plus `0.0.0.0`)
- Config Nginx fournie (`nginx_safetymonitor.conf`) avec redirect HTTP → HTTPS
- TLS 1.2/1.3 uniquement, ciphers modernes
- Headers sécurité : HSTS, X-Frame-Options, X-Content-Type-Options

### Ch.2 — AAA (Authentication, Authorization, Accounting)
- **Authentication** : page login (`/login`) avec session Flask-Login
- **Authorization** : routes `/`, `/monitor`, `/api/analyze` protégées par `@login_required`
  - Rôle `admin` : accès aux logs, gestion des utilisateurs
  - Rôle `viewer` : accès lecture seule au moniteur
- **Accounting** : chaque événement (login, logout, analyse, erreur) est loggé dans `audit.log` et la table `audit_events`
- Rate limiting : `/api/analyze` limité à 20/min, `/api/login` à 10/min

### Ch.3 — ACL
- CORS restreint aux origines configurées (variable `ALLOWED_ORIGINS`)
- Fichiers `.pt` bloqués au niveau Nginx et Flask
- Fichiers `.db` et `.log` bloqués par Nginx
- Décorateur `@admin_required` pour les routes d'administration

### Ch.4 — Pare-feux
- Validation MIME + taille des images (max 10MB, types autorisés seulement)
- Nginx : `client_max_body_size 10M`
- Variables d'environnement pour les secrets (plus de valeurs hardcodées)
- `debug=False` imposé en production

---

## Installation

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Lancer (dev — HTTP)
python app.py

# 3. Lancer (prod — avec HTTPS forcé)
FORCE_HTTPS=1 SECRET_KEY=votre_clé_aléatoire python app.py
```

## Compte par défaut

| Username | Password  | Rôle  |
|----------|-----------|-------|
| admin    | admin123  | admin |

⚠️ **Changer le mot de passe immédiatement** via l'API admin ou en base.

## Base de données SQLite (`safetymonitor.db`)

Trois tables créées automatiquement :
- `users` — identifiants, rôles, dernière connexion
- `audit_events` — chaque action loggée (qui, quand, depuis quelle IP)
- `analyses` — historique des analyses (score, niveau, nb personnes)

## Variables d'environnement

| Variable          | Défaut                  | Description                    |
|-------------------|-------------------------|--------------------------------|
| `SECRET_KEY`      | aléatoire à chaque boot | Clé de signature des sessions  |
| `FORCE_HTTPS`     | `0`                     | Mettre `1` en production       |
| `ALLOWED_ORIGINS` | `http://localhost:5000` | Origines CORS autorisées       |

## Structure des fichiers

```
safetymonitor_web/
├── app.py                    ← backend sécurisé (NOUVEAU)
├── requirements.txt          ← dépendances mises à jour (NOUVEAU)
├── nginx_safetymonitor.conf  ← config Nginx HTTPS (NOUVEAU)
├── safetymonitor.db          ← base de données auto-créée
├── audit.log                 ← logs de sécurité auto-créés
├── vew.pt                    ← modèle PPE (existant)
├── scafandri.pt              ← modèle échafaudages (existant)
└── static/
    ├── login.html            ← page login (NOUVEAU)
    ├── index.html            ← landing page (existant)
    └── monitor.html          ← dashboard (existant)
```
