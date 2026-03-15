@echo off
chcp 65001 >nul 2>&1
REM ══════════════════════════════════════════════════════════════════
REM  NetSleuth — Deploy to GitHub (Windows)
REM  
REM  This script automates:
REM    1. .gitignore generation
REM    2. Git repository initialization
REM    3. Initial commit
REM    4. Remote configuration (asks for repo URL)
REM    5. Push to main
REM    6. Tag v1.0.0 creation and push
REM
REM  Usage:  deploy.bat
REM  Requirements: Git for Windows must be installed and in PATH.
REM ══════════════════════════════════════════════════════════════════

echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║   NetSleuth — Deploy to GitHub                       ║
echo  ║   v1.0.0 Release                                     ║
echo  ╚══════════════════════════════════════════════════════╝
echo.

REM ── Step 0: Verify Git is installed ──────────────────────────────
where git >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo  [ERROR] Git no esta instalado o no esta en el PATH.
    echo  Descargalo de: https://git-scm.com/downloads
    pause
    exit /b 1
)
echo  [OK] Git encontrado: 
git --version
echo.

REM ── Step 1: Generate .gitignore ──────────────────────────────────
echo  [1/6] Generando .gitignore...

(
echo # ═══ Python ═══
echo __pycache__/
echo *.py[cod]
echo *$py.class
echo *.pyo
echo *.pyd
echo.
echo # ═══ Virtual Environments ═══
echo env/
echo venv/
echo .venv/
echo ENV/
echo.
echo # ═══ IDE / Editor ═══
echo .vscode/
echo .idea/
echo *.swp
echo *.swo
echo *~
echo .DS_Store
echo Thumbs.db
echo.
echo # ═══ Distribution / Build ═══
echo dist/
echo build/
echo *.egg-info/
echo *.egg
echo.
echo # ═══ Logs ═══
echo *.log
echo.
echo # ═══ OS Files ═══
echo .DS_Store
echo Desktop.ini
) > .gitignore

if %ERRORLEVEL% neq 0 (
    echo  [ERROR] No se pudo crear .gitignore
    pause
    exit /b 1
)
echo  [OK] .gitignore creado.
echo.

REM ── Step 2: Initialize Git ──────────────────────────────────────
echo  [2/6] Inicializando repositorio Git...

if exist .git (
    echo  [INFO] Repositorio Git ya existe, omitiendo git init.
) else (
    git init
    if %ERRORLEVEL% neq 0 (
        echo  [ERROR] git init fallo.
        pause
        exit /b 1
    )
)
echo  [OK] Repositorio Git listo.
echo.

REM ── Step 3: Stage all files ─────────────────────────────────────
echo  [3/6] Agregando archivos al staging area...

git add -A
if %ERRORLEVEL% neq 0 (
    echo  [ERROR] git add fallo.
    pause
    exit /b 1
)
echo  [OK] Archivos agregados.
echo.

REM ── Step 4: Initial commit ──────────────────────────────────────
echo  [4/6] Creando commit inicial...

git commit -m "feat: NetSleuth v1.0.0 — Passive/Active Scanner + Stress Test + Web Dashboard" -m "Phase 1: Clean Architecture base, ARP/DHCP/TCP passive analyzers, CLI" -m "Phase 2: Active scanner (fire-and-forget ARP sweep + TCP SYN probes)" -m "Phase 3: Stress test module (raw socket UDP flood, 100K+ PPS)" -m "Phase 4: FastAPI web dashboard with real-time WebSocket telemetry"
if %ERRORLEVEL% neq 0 (
    echo  [WARN] Commit fallo, quizas no hay cambios nuevos.
    echo         Continuando...
)
echo  [OK] Commit creado.
echo.

REM ── Step 5: Configure remote and push ───────────────────────────
echo  [5/6] Configurando repositorio remoto...
echo.

REM  Check if remote 'origin' already exists
git remote get-url origin >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo  [INFO] Remote 'origin' ya configurado:
    git remote get-url origin
    echo.
    set /p CHANGE_REMOTE="  Deseas cambiarlo? (s/N): "
    if /i "%CHANGE_REMOTE%"=="s" (
        set /p REPO_URL="  Nueva URL del repositorio: "
        git remote set-url origin "%REPO_URL%"
    )
) else (
    set /p REPO_URL="  Pega la URL del repositorio GitHub: "
    git remote add origin "%REPO_URL%"
    if %ERRORLEVEL% neq 0 (
        echo  [ERROR] No se pudo agregar el remote.
        pause
        exit /b 1
    )
)

REM  Rename branch to main if needed
git branch -M main

echo.
echo  Haciendo push a main...
git push -u origin main
if %ERRORLEVEL% neq 0 (
    echo  [ERROR] Push fallo. Verifica:
    echo    - La URL del repositorio es correcta
    echo    - Tienes permisos de escritura
    echo    - Tu autenticacion Git esta configurada (SSH key o token)
    pause
    exit /b 1
)
echo  [OK] Push exitoso.
echo.

REM ── Step 6: Create and push tag ─────────────────────────────────
echo  [6/6] Creando tag v1.0.0...

git tag -a v1.0.0 -m "Release v1.0.0 — NetSleuth: Full network recon suite with web dashboard"
if %ERRORLEVEL% neq 0 (
    echo  [WARN] Tag v1.0.0 ya existe o no se pudo crear.
) else (
    echo  [OK] Tag v1.0.0 creado.
)

git push origin v1.0.0
if %ERRORLEVEL% neq 0 (
    echo  [WARN] No se pudo subir el tag.
) else (
    echo  [OK] Tag v1.0.0 subido.
)

echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║   DEPLOY COMPLETADO                                  ║
echo  ║                                                      ║
echo  ║   Repo:  origin/main                                 ║
echo  ║   Tag:   v1.0.0                                      ║
echo  ║                                                      ║
echo  ║   Siguiente paso:                                    ║
echo  ║   → Crea un Release en GitHub con release_v1.md      ║
echo  ║   → Ejecuta install.sh en tu VM de Kali Linux        ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
pause
