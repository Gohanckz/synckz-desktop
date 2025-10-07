# 🔗 Integración Completa: Desktop App ↔ Django Backend

## 📋 Resumen

Se ha implementado exitosamente una **arquitectura de autenticación híbrida** que permite que usuarios registrados en **synckz.com** (Django/PostgreSQL) puedan iniciar sesión en **Synckz Desktop** (Go/SQLite) sin duplicar cuentas.

---

## ✅ Cambios Implementados

### 🎯 Proyecto Desktop App (synckz-desktop)

#### Archivos Nuevos

1. **`backend/auth-service/django_client.go`**
   - Cliente HTTP para comunicación con Django API
   - Funciones: `AuthenticateWithDjango()`, `VerifyDjangoToken()`
   - Manejo de errores y timeouts

#### Archivos Modificados

2. **`backend/auth-service/main.go`**
   - ✅ Variables globales para Django integration
   - ✅ Función `initDjangoClient()` para inicializar cliente Django
   - ✅ Lógica de autenticación híbrida en `loginHandler()`:
     ```
     1. Buscar usuario en SQLite local (demo users)
     2. Si no existe → Autenticar con Django API
     3. Si Django auth exitosa → Sincronizar a SQLite
     4. Generar JWT local y permitir acceso
     ```

#### Variables de Entorno Nuevas

```bash
# .env o sistema
DJANGO_API_URL="https://synckz.com/api/v1/desktop"  # URL de la API Django
DJANGO_AUTH_ENABLED="true"                           # Habilitar Django auth
JWT_SECRET="shared_jwt_secret_for_testing_123"       # Secret para JWT
AUTH_PORT=8081                                        # Puerto del servicio
```

---

### 🌐 Proyecto Django (synckz)

#### Archivos Nuevos para GitHub

1. **`registration/api_views.py`** (9.6 KB)
   - Endpoints REST para desktop app:
     - `POST /api/v1/desktop/auth/login/` - Autenticar usuario
     - `POST /api/v1/desktop/auth/verify-token/` - Verificar JWT
     - `GET /api/v1/desktop/auth/user-profile/` - Obtener perfil
     - `POST /api/v1/desktop/auth/logout/` - Cerrar sesión
     - `GET /api/v1/desktop/health/` - Health check

2. **`registration/api_urls.py`** (609 bytes)
   - Configuración de URLs para la API
   - Mapeo de endpoints a views

3. **`registration/serializers.py`** (1.3 KB)
   - `UserSerializer` - Serializa CustomUser a JSON
   - `LoginSerializer` - Valida requests de login
   - `TokenVerifySerializer` - Valida tokens JWT

#### Archivos a Modificar (instrucciones en guía)

4. **`huntersbook/settings.py`**
   - Agregar `rest_framework` a `INSTALLED_APPS`
   - Configuración de Django REST Framework
   - Variables de JWT para desktop app

5. **`huntersbook/urls.py`**
   - Incluir URLs de la API: `path('api/v1/desktop/', include('registration.api_urls'))`

6. **`requirements.txt`**
   - Agregar `djangorestframework==3.14.0`
   - Agregar `PyJWT==2.8.0`

---

## 🔐 Flujo de Autenticación Híbrida

### Escenario 1: Usuario Django (Primera Vez)

```
┌──────────────┐
│   Usuario    │  Email: owner@synckz.com
│              │  Password: ********
└──────┬───────┘
       │
       ▼
┌─────────────────────────────────────────┐
│   Desktop App Frontend (React)          │
│   POST localhost:8081/auth/login        │
└─────────────┬───────────────────────────┘
              │
              ▼
┌────────────────────────────────────────────────────┐
│   Go Auth Service (:8081)                          │
│                                                    │
│   1. Buscar email en SQLite local                 │
│      → NO ENCONTRADO                               │
│                                                    │
│   2. djangoEnabled = true?                         │
│      → SÍ → Llamar a Django API                   │
└─────────────┬──────────────────────────────────────┘
              │ HTTPS
              ▼
┌────────────────────────────────────────────────────┐
│   Django API (https://synckz.com)                  │
│   POST /api/v1/desktop/auth/login/                 │
│                                                    │
│   1. Verificar email en PostgreSQL                 │
│   2. Verificar password (PBKDF2)                   │
│   3. Generar JWT Django                            │
│   4. Responder con user data                       │
└─────────────┬──────────────────────────────────────┘
              │
              ▼
┌────────────────────────────────────────────────────┐
│   Go Auth Service                                  │
│                                                    │
│   3. Django auth exitosa                           │
│      → Guardar usuario en SQLite:                  │
│        - ID de Django                              │
│        - Email, username, level, credits           │
│        - SIN password hash (usuarios Django)       │
│                                                    │
│   4. Generar JWT local (Go)                        │
│   5. Responder al frontend                         │
└─────────────┬──────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│   Desktop App Frontend                  │
│                                         │
│   - Almacenar JWT en localStorage       │
│   - Redirigir a dashboard               │
│   - Usuario autenticado ✅              │
└─────────────────────────────────────────┘
```

### Escenario 2: Usuario Local (Demo)

```
Usuario: admin@synckz.com / admin123
    │
    ▼
Go Auth Service
    │
    ├──> Buscar en SQLite → ENCONTRADO
    │
    ├──> Verificar password con Bcrypt → OK
    │
    ├──> Generar JWT local
    │
    └──> Responder (sin llamar a Django)
```

### Escenario 3: Usuario Django (Ya Sincronizado)

```
Usuario: owner@synckz.com / ******** (segunda vez)
    │
    ▼
Go Auth Service
    │
    ├──> Buscar en SQLite → ENCONTRADO (hashedPassword = "")
    │
    ├──> Detectar que es usuario Django
    │
    ├──> Revalidar con Django API ──> Django verifica password
    │
    ├──> Actualizar datos locales (level, credits pueden cambiar)
    │
    ├──> Generar JWT local
    │
    └──> Responder
```

---

## 📦 Archivos para Despliegue

### Para GitHub (repositorio synckz)

Los siguientes archivos están listos para commit en `/tmp/django-integration-files/`:

```
/tmp/django-integration-files/
├── registration/
│   ├── api_views.py       # Endpoints REST
│   ├── api_urls.py         # URLs de la API
│   └── serializers.py      # Serializadores DRF
└── DJANGO_DEPLOYMENT_GUIDE.md  # Guía completa de despliegue
```

### Comando para Copiar Archivos a Django Repo

```bash
# Navegar al repositorio de Django
cd /ruta/a/tu/repo/synckz

# Copiar archivos
cp /tmp/django-integration-files/registration/api_views.py registration/
cp /tmp/django-integration-files/registration/api_urls.py registration/
cp /tmp/django-integration-files/registration/serializers.py registration/

# Commit y push
git add registration/api_views.py registration/api_urls.py registration/serializers.py
git commit -m "Add Desktop App REST API for hybrid authentication

- Add REST API endpoints for Synckz Desktop authentication
- Support hybrid auth: local JWT + Django PostgreSQL validation
- Endpoints: login, verify-token, user-profile, logout, health
- JWT token generation for desktop app sessions
- Secure password validation with PBKDF2
- Rate limiting and error handling

Related to: synckz-desktop integration"

git push origin main
```

---

## 🚀 Cómo Iniciar Todo

### 1. Iniciar Desktop App (Desarrollo)

```bash
# Terminal 1: Frontend
cd frontend
npm run dev

# Terminal 2: Auth Service (con Django habilitado)
cd backend/auth-service
DJANGO_API_URL="https://synckz.com/api/v1/desktop" \
DJANGO_AUTH_ENABLED="true" \
JWT_SECRET="shared_jwt_secret_for_testing_123" \
AUTH_PORT=8081 \
go run *.go

# Terminales 3-11: Otros microservicios
# (subdomain-service, dork-service, methodology-service, etc.)
```

### 2. Desplegar API en Django (Producción)

Sigue la guía completa en: `/tmp/django-integration-files/DJANGO_DEPLOYMENT_GUIDE.md`

**Pasos rápidos:**

```bash
# En el servidor de producción
ssh usuario@synckz.com

# Instalar dependencias
cd /ruta/a/synckz
pip install djangorestframework PyJWT

# Copiar archivos (vía git pull después del commit)
git pull origin main

# Configurar settings.py (agregar DRF y JWT config)
# Configurar urls.py (incluir api_urls.py)
# Configurar .env.prod (agregar DESKTOP_JWT_SECRET)

# Reiniciar servidor
sudo systemctl restart gunicorn
```

### 3. Verificar Integración

```bash
# Health check de Django API
curl https://synckz.com/api/v1/desktop/health/

# Respuesta esperada:
# {
#   "status": "healthy",
#   "service": "synckz-desktop-api",
#   "version": "1.0.0",
#   "timestamp": "2025-01-07T..."
# }

# Probar login con usuario Django
curl -X POST https://synckz.com/api/v1/desktop/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "owner@synckz.com",
    "password": "tu_password"
  }'

# Si funciona, deberías recibir:
# {
#   "success": true,
#   "access_token": "eyJhbGci...",
#   "user": { ... }
# }
```

---

## 🔧 Configuración de Variables de Entorno

### Desktop App

Crear `.env` en la raíz del proyecto o configurar en el sistema:

```bash
# Auth Service
JWT_SECRET="shared_jwt_secret_for_testing_123"
AUTH_PORT=8081

# Django Integration
DJANGO_API_URL="https://synckz.com/api/v1/desktop"
DJANGO_AUTH_ENABLED="true"
```

### Django (`.env.prod`)

```bash
# Existentes...
SECRET_KEY="..."
DEBUG=False
ALLOWED_HOSTS="synckz.com,www.synckz.com"

# Nuevas para Desktop App
DESKTOP_JWT_SECRET="GENERAR_UNO_NUEVO_Y_SEGURO_AQUI"
DESKTOP_JWT_EXPIRATION=86400  # 24 horas
DESKTOP_APP_ALLOWED_ORIGINS="http://localhost:5177"
```

---

## 📊 Estado de la Integración

### ✅ Completado

- [x] API REST en Django (api_views.py, api_urls.py, serializers.py)
- [x] Cliente Django en Go (django_client.go)
- [x] Autenticación híbrida en auth-service (main.go)
- [x] Sincronización de usuarios Django → SQLite
- [x] Generación de JWT local para sesiones
- [x] Documentación completa de despliegue
- [x] Documentación de integración

### 🚧 Pendiente (Opcional)

- [ ] Desplegar API en producción (synckz.com)
- [ ] Probar login con usuarios Django reales
- [ ] Implementar sincronización bidireccional
- [ ] Implementar refresh tokens
- [ ] Sincronización de walkthroughs Desktop → Django
- [ ] Sincronización de subdomains encontrados

---

## 🎯 Resultado Final

**Comportamiento esperado:**

1. Usuario se registra en **synckz.com** (web)
2. Descarga **Synckz Desktop** (ejecutable)
3. Inicia sesión con email/password de synckz.com
4. Desktop app autentica con Django API
5. Usuario sincronizado a SQLite local
6. JWT generado para sesión local
7. Usuario puede trabajar en la app de escritorio ✅

**Sin duplicación:**
- ❌ NO necesita crear cuenta separada
- ✅ Una sola identidad: synckz.com
- ✅ Datos de perfil sincronizados (level, credits, team)

---

## 📞 Soporte

**Archivos de referencia:**
- `docs/DJANGO-AUTH-INTEGRATION-PLAN.md` - Plan completo de integración
- `/tmp/django-integration-files/DJANGO_DEPLOYMENT_GUIDE.md` - Guía de despliegue Django
- `backend/auth-service/django_client.go` - Cliente HTTP Django
- `backend/auth-service/main.go` - Lógica de auth híbrida

**Testing:**
- Endpoint local: `http://localhost:8081/health`
- Endpoint Django: `https://synckz.com/api/v1/desktop/health/`

---

**Creado por:** Claude Code
**Fecha:** 2025-01-07
**Versión:** 1.0
**Repositorios:**
- Desktop: https://github.com/Gohanckz/synckz-desktop
- Django: https://github.com/Gohanckz/synckz
