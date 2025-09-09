# AD-UserDevice

Script de PowerShell para operaciones rápidas sobre Active Directory: listar y auditar usuarios y equipos, detectar inactividad, bloqueos y deshabilitados, agrupar equipos por sistema operativo, comprobar hosts offline y exportar resultados a CSV/TXT. Incluye validaciones de entrada, manejo básico de errores y menú interactivo.

## Características
- Usuarios:
  - Listado general con Enabled y LastLogon
  - Inactivos por N días
  - Bloqueados
  - Deshabilitados
  - PasswordNeverExpires
  - Contraseñas por expirar en N días
- Equipos:
  - Listado general con OS y LastLogon
  - Inactivos por N días
  - Conteo por sistema operativo
  - Heurística de “largo uptime” usando LastLogonDate
  - Offline (ICMP) con timeout por host
  - Filtrado por OU
- Exportación opcional a TXT/CSV en el Escritorio con timestamp
- Codificación UTF-8 BOM y salida ordenada

## Requisitos
- Windows con PowerShell 5.1 o superior
- RSAT con el módulo ActiveDirectory instalado
- Permisos de lectura en el dominio y conectividad a los DCs

## Instalación
1. Clonar este repositorio.
2. Opcional en la sesión actual:
   - Set-ExecutionPolicy -Scope Process RemoteSigned
3. Ubicar el script en src/AD-QuickOps.ps1 (o el nombre elegido).

## Uso rápido
1. Abrir PowerShell con una cuenta con permisos de lectura en AD.
2. Ejecutar:
   - .\src\AD-QuickOps.ps1
3. Navegar por el menú:
   - Usuarios: listar todos, inactivos (X días), bloqueados, deshabilitados, PasswordNeverExpires, por expirar (X días).
   - Equipos: listar todos, inactivos (X días), por OS, “sin reinicio” (proxy), offline, en OU.
4. Exportación:
   - Tras cada reporte, elegir “txt”, “csv” o “no”. Se guardará en el Escritorio con prefijo y marca de tiempo (YYYYMMDD_HHMM).
