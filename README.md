# Weeb Backend — Django 5 + DRF + SimpleJWT (cookies) + Docker

Backend sécurisé pour le front-end **weeb-website**.  
Authentification **JWT** stockée dans des **cookies HttpOnly** (et `Secure` en production), avec **CSRF** actif.

## ✨ Fonctionnalités

- Login / Refresh / Logout avec **JWT en cookies HttpOnly**
- Endpoint `/me` protégé (retourne le profil)
- Inscription avec **validation forte** :
  - champs obligatoires : `username`, `email`, `first_name`, `last_name`, `password`, `password_confirm`
  - email **valide** et **unique** (insensible à la casse)
  - **politiques de mot de passe** Django
- **CSRF** prêt pour les requêtes mutantes (POST/PUT/PATCH/DELETE)
- **CORS** configurable (origines autorisées)
- **Tests unitaires + coverage** (rapport CLI + HTML)
- Docker / docker-compose (dev & prod)

---

## 🏗️ Stack

- **Python / Django 5.x**
- **Django REST Framework**
- **SimpleJWT** (JWT + rotation / blacklist optionnelle)
- **django-cors-headers**
- **SQLite (dev)** → **PostgreSQL (prod recommandé)**
- **Docker / docker-compose**

---

## 📦 Structure (extrait)

```
config/
  settings.py
  urls.py
users/
  auth.py          # Auth DRF: header Bearer puis fallback cookie
  views.py         # login, refresh, logout, me, csrf, health, register
  urls.py
  serializers.py
  tests/
    test_auth.py
    test_edges.py
```

---

## 🔧 Prérequis

- Docker & docker-compose
- (Optionnel) Python 3.14+ si tu veux lancer sans Docker

---

## 🚀 Installation & démarrage

1) **Clone**
```bash
git clone <ton-repo> weeb-backend
cd weeb-backend
```

2) **Variables d’environnement**  
Crée `.env` à partir d’un exemple :

```bash
cp .env.example .env
```

Exemple minimal :
```env
# Django
DJANGO_SECRET_KEY=change-me
DJANGO_DEBUG=1
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1

# CORS / CSRF (mets l'URL de ton front)
CORS_ALLOWED_ORIGINS=http://localhost:3000
CSRF_TRUSTED_ORIGINS=http://localhost:3000

# Cookies (prod: True)
CSRF_COOKIE_SECURE=False
SESSION_COOKIE_SECURE=False

# Port (optionnel selon ton compose)
BACKEND_PORT=8000
```

> En **prod** : mets `DJANGO_DEBUG=0`, configure **HTTPS** et `*_COOKIE_SECURE=True`.

3) **Lancer**
```bash
docker compose up --build
```
API dispo sur `http://localhost:8000` (ou `BACKEND_PORT`).

---

## 🔐 Endpoints d’auth

Base : `/api/auth/`

### 1) CSRF
- **GET** `/csrf/` → pose un cookie `csrftoken` et renvoie `{"csrfToken": "..."}`
- Utilise ensuite ce token dans l’en-tête `X-CSRFToken` pour les requêtes **mutantes**.

### 2) Register (création de compte)
- **POST** `/register/`
- **Headers** : `Content-Type: application/json`, `X-CSRFToken: <csrftoken>`
- **Body**
```json
{
  "username": "test",
  "email": "test@example.com",
  "first_name": "test",
  "last_name": "Test",
  "password": "StrongPass123!",
  "password_confirm": "StrongPass123!"
}
```
- **Réponses**
  - `201 Created` → `{ "detail": "registered" }` + cookies `access` et `refresh` (HttpOnly)
  - `400` → erreurs de champs (`email`, `password_confirm`, etc.)

### 3) Login
- **POST** `/login/`
- **Headers** : `Content-Type: application/json`, `X-CSRFToken`
- **Body**
```json
{ "username": "test", "password": "StrongPass123!" }
```
- **Réponse** : `200 OK` → `{ "detail": "logged_in" }` + cookies posés

### 4) Refresh
- **POST** `/refresh/`
- **Headers** : `X-CSRFToken`
- **Body** : vide **ou** `{ "refresh": "<token>" }`  
  (si le body ne fournit rien, le backend lit le cookie `refresh`)
- **Réponse** : `200 OK` → `{ "detail": "refreshed" }` + nouveau cookie `access`

### 5) Logout
- **POST** `/logout/`
- **Headers** : `X-CSRFToken`
- **Réponse** : `200 OK` → `{ "detail": "logged_out" }` + cookies supprimés

### 6) Profil
- **GET** `/me/`
- **Réponse** :
```json
{
  "id": 1,
  "username": "test",
  "email": "test@example.com",
  "first_name": "test",
  "last_name": "Test"
}
```

### 7) Health check
- **GET** `/health/` → `{ "ok": true, "version": "..." }`

---

## 🧪 Tests & Coverage

Lancer les tests :
```bash
docker compose run --rm api python manage.py test users -v 2
```

Avec **coverage** :
```bash
docker compose run --rm api bash -lc "
coverage erase && \
coverage run manage.py test users -v 2 && \
coverage report -m && \
coverage html && \
ls -la coverage_html | head -n 20
"
```

- Rapport textuel : `coverage report -m`
- Rapport HTML : `coverage_html/index.html`

> Dans `.coveragerc`, adapte `fail_under` (ex. `85` → `100` si tu veux être strict).

---

## 🤝 Intégration Front-end (fetch + cookies + CSRF)

- **Inclure les cookies** côté front :
```ts
fetch("http://localhost:8000/api/auth/me/", {
  credentials: "include", // IMPORTANT
});
```

- **CSRF** pour POST/PUT/PATCH/DELETE :
  1. Appeler `GET /api/auth/csrf/` une fois au démarrage (le backend pose `csrftoken`)
  2. Lire le cookie `csrftoken` (non-HttpOnly) et l’envoyer dans l’en-tête :
```ts
headers: {
  "Content-Type": "application/json",
  "X-CSRFToken": readCookie("csrftoken"),
}
```

- **JWT** : ne **jamais** lire/écrire en JS — ils sont en **HttpOnly**.  
- **Refresh** : le front peut appeler périodiquement `/refresh/` (ou au 401) pour regénérer `access`.

---

## ⚙️ Variables importantes (rappel)

- `DJANGO_SECRET_KEY` : **obligatoire** en prod
- `DJANGO_DEBUG` : `0` en prod
- `DJANGO_ALLOWED_HOSTS` : ex. `api.example.com`
- `CORS_ALLOWED_ORIGINS` : ex. `https://app.example.com`
- `CSRF_TRUSTED_ORIGINS` : ex. `https://app.example.com`
- Cookies (prod) : `CSRF_COOKIE_SECURE=True`, `SESSION_COOKIE_SECURE=True`, `SIMPLE_JWT.AUTH_COOKIE_SECURE=True`

**SIMPLE_JWT (extrait dans `settings.py`)**
- `ACCESS_TOKEN_LIFETIME`: 15 min (reco)
- `REFRESH_TOKEN_LIFETIME`: 7 jours (exemple)
- `ROTATE_REFRESH_TOKENS`: `True` (optionnel)
- `BLACKLIST_AFTER_ROTATION`: `True` (si rotation)
- **Cookies** :
  - `AUTH_COOKIE` = `access`
  - `AUTH_COOKIE_REFRESH` = `refresh`
  - `AUTH_COOKIE_HTTP_ONLY` = `True`
  - `AUTH_COOKIE_SECURE` = `True` (prod)
  - `AUTH_COOKIE_SAMESITE` = `Lax`

> Si tu actives le **blacklisting**, ajoute `rest_framework_simplejwt.token_blacklist` dans `INSTALLED_APPS` et exécute les migrations.

---

## 🗃️ Base de données

### Dev (par défaut) : SQLite
Aucune config supplémentaire (fichier `db.sqlite3`).

### Prod (recommandé) : PostgreSQL
Exemple de service `docker-compose.yml` :

```yaml
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_DB: weeb
      POSTGRES_USER: weeb
      POSTGRES_PASSWORD: change-me
    volumes:
      - dbdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  api:
    build: .
    env_file: .env
    depends_on:
      - db
    ports:
      - "${BACKEND_PORT:-8000}:8000"
    # command: gunicorn config.wsgi:application -b 0.0.0.0:8000 --workers 3

volumes:
  dbdata:
```

Adapte `DATABASES` dans `settings.py` si tu passes à Postgres, par ex. :

```py
import os
if os.getenv("DJANGO_DB_ENGINE") == "postgres":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("POSTGRES_DB", "weeb"),
            "USER": os.getenv("POSTGRES_USER", "weeb"),
            "PASSWORD": os.getenv("POSTGRES_PASSWORD", ""),
            "HOST": os.getenv("POSTGRES_HOST", "db"),
            "PORT": os.getenv("POSTGRES_PORT", "5432"),
        }
    }
```
---

## 🔒 Bonnes pratiques sécurité (prod)

- `DJANGO_DEBUG=0`
- **HTTPS** obligatoire (reverse proxy ou CDN), avec `*_COOKIE_SECURE=True`
- Origines **CORS/CSRF** limitées au strict nécessaire
- **HttpOnly** pour les JWT, **ne jamais** exposer les tokens dans le body
- Durée de vie d’`access` courte (ex. 15 min), `refresh` modérée (ex. 7 j)
- (Optionnel) **Rotation + blacklist** des refresh tokens
- Entêtes de sécurité au niveau reverse proxy (CSP, HSTS, etc.)
- Journaux d’accès et **rate limiting** (via proxy ou DRF throttling)

---

## 🧰 Commandes utiles

Migrations :
```bash
docker compose run --rm api python manage.py migrate
docker compose run --rm api python manage.py createsuperuser
```

Tests :
```bash
docker compose run --rm api python manage.py test users -v 2
```

Coverage :
```bash
docker compose run --rm api bash -lc "coverage erase && coverage run manage.py test users -v 2 && coverage report -m && coverage html"
```

Collect static (si tu en as) :
```bash
docker compose run --rm api python manage.py collectstatic --noinput
```

---

## 🧪 Postman (astuce)

1. **GET** `/api/auth/csrf/` → init Cookie Jar avec `csrftoken`  
2. Pour chaque **POST/PUT/PATCH/DELETE** : ajoute l’en-tête `X-CSRFToken` avec la valeur du cookie  
3. Les cookies `access`/`refresh` sont **HttpOnly** : invisibles dans le body, mais **Postman les enverra automatiquement**

---

## 🩹 Dépannage

- **404 sur `/register`** : appelle bien `/api/auth/register/` **avec le slash final** ou utilise le `re_path` tolérant.
- **`'Request' object has no attribute 'settings'`** : ne jamais lire `request.settings`. Utilise `from django.conf import settings`.
- **CSRF 403** : assure-toi d’avoir appelé `/csrf/` et d’envoyer `X-CSRFToken` **+** `credentials: 'include'`.
- **Cookies non posés en local** : si tu es en **HTTP**, mets temporairement `CSRF_COOKIE_SECURE=False`, `SESSION_COOKIE_SECURE=False`, `SIMPLE_JWT["AUTH_COOKIE_SECURE"]=False`.
- **CORS** : configure `CORS_ALLOWED_ORIGINS` et `CSRF_TRUSTED_ORIGINS` avec l’URL exacte du front.

---


