# SafetyMonitor Web — v12

AI Construction Site Safety Monitor avec Flask backend.

## 🚀 Démarrage rapide

```bash
cd safetymonitor_web
pip install -r requirements.txt
python app.py
```

Ouvrir : **http://localhost:5000/login**

Compte admin par défaut : `admin` / `admin123`  
⚠️ Changer immédiatement en production !

---

## 📧 Configuration Email (inscription)

Copier `.env.example` en `.env` et remplir les valeurs :

```bash
cp .env.example .env
```

Installer python-dotenv pour charger le `.env` :

```bash
pip install python-dotenv
```

### Gmail — Mot de passe d'application

1. Aller sur [myaccount.google.com](https://myaccount.google.com)
2. **Sécurité** → **Validation en deux étapes** (activer)
3. **Mots de passe des applications** → Créer un mot de passe pour "SafetyMonitor"
4. Utiliser ce mot de passe dans `SMTP_PASSWORD`

> **Mode développement** : si `SMTP_USER` / `SMTP_PASSWORD` ne sont pas configurés,  
> le code de vérification s'affiche dans la console du serveur.

---

## 📄 Pages

| URL | Description |
|---|---|
| `/login` | Page de connexion |
| `/register` | Inscription (vérification email en 2 étapes) |
| `/` | Dashboard (index) |
| `/monitor` | Analyse de chantier |

---

## 🔌 API

| Méthode | Route | Description |
|---|---|---|
| POST | `/api/login` | Connexion (10/min) |
| POST | `/api/register` | Étape 1 : envoi code email (5/min) |
| POST | `/api/verify-email` | Étape 2 : valider code → créer compte (10/min) |
| POST | `/api/logout` | Déconnexion |
| GET  | `/api/me` | Infos utilisateur courant |
| POST | `/api/analyze` | Analyser une image (20/min, auth) |
| GET  | `/api/status` | Statut serveur |
| GET  | `/api/admin/users` | Lister les utilisateurs (admin) |
| POST | `/api/admin/users` | Créer un utilisateur (admin) |
| DELETE | `/api/admin/users/<id>` | Supprimer un utilisateur (admin) |
| GET  | `/api/admin/logs` | Logs d'audit (admin) |
| GET  | `/api/admin/analyses` | Historique analyses (admin) |

---

## 🗃️ Base de données SQLite

Tables créées automatiquement au premier lancement :

- `users` — comptes utilisateurs (username, password_hash, role, email)
- `email_verifications` — codes de vérification temporaires (15 min)
- `audit_events` — journal des actions
- `analyses` — historique des analyses IA

---

## ⚙️ Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `SECRET_KEY` | aléatoire | Clé session Flask |
| `SMTP_HOST` | smtp.gmail.com | Serveur SMTP |
| `SMTP_PORT` | 587 | Port SMTP |
| `SMTP_USER` | *(vide)* | Email expéditeur |
| `SMTP_PASSWORD` | *(vide)* | Mot de passe app SMTP |
| `EMAIL_FROM` | = SMTP_USER | Adresse "De :" |
| `ADMIN_REG_CODE` | SAFETYMONITOR_ADMIN_2024 | Code pour rôle Admin |
| `FORCE_HTTPS` | `0` | Mettre `1` en production |

---

## 🤖 Modèles IA requis

- `vew.pt` — détection EPI
- `scafandri.pt` — détection échafaudages
