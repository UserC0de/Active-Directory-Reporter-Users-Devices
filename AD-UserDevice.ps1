<#
.SYNOPSIS
Gestión de Usuarios y Equipos en Active Directory

.DESCRIPTION
Reportes operativos de usuarios y equipos (inactividad, bloqueo, deshabilitados,
OS, “offline”, etc.) con exportación opcional a TXT/CSV.

.REQUISITOS
- PowerShell 5.1+ recomendado
- RSAT ActiveDirectory module instalado
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err ($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red }

# Validar módulo ActiveDirectory
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Err "No se encuentra el módulo ActiveDirectory (RSAT)."
    return
}

# -------- Exportación --------
function Exportar-Resultados {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]] $Datos,
        [Parameter(Mandatory)][string]   $Prefijo
    )
    try {
        $op = Read-Host "Exportar resultados? (txt/csv/no)"
        $timestamp = (Get-Date -Format 'yyyyMMdd_HHmm')
        $desktop = [Environment]::GetFolderPath('Desktop')
        switch ($op) {
            'txt' {
                $ruta = Join-Path $desktop "$($Prefijo)_$timestamp.txt"
                # Out-String asegura texto legible en TXT
                $Datos | Out-String | Out-File -FilePath $ruta -Encoding utf8BOM
                Write-Info "Exportado en TXT: $ruta"
            }
            'csv' {
                $ruta = Join-Path $desktop "$($Prefijo)_$timestamp.csv"
                # Export-Csv con UTF8-BOM y cultura invariante
                $Datos | Export-Csv -Path $ruta -NoTypeInformation -Encoding utf8BOM -UseCulture:$false
                Write-Info "Exportado en CSV: $ruta"
            }
            default {
                Write-Info "No se exportaron los resultados."
            }
        }
    } catch {
        Write-Err "Fallo exportando: $($_.Exception.Message)"
    } finally {
        Pause
    }
}

# ---------- Funciones Usuarios ----------
function Listar-Usuarios {
    [CmdletBinding()]
    param()
    $result = Get-ADUser -Filter * -Properties Enabled,LastLogonDate,SamAccountName,DisplayName |
        Select-Object @{Name='Name';Expression={$_.DisplayName}},SamAccountName,Enabled,@{Name='LastLogon';Expression={$_.LastLogonDate}}
    if (-not $result -or $result.Count -eq 0) {
        Write-Host "No se encontraron usuarios"
        Pause
        return
    }
    $result | Sort-Object Name | Format-Table -AutoSize
    $count = $result.Count
    Write-Host "Total usuarios encontrados: $count"
    Exportar-Resultados -Datos $result -Prefijo 'Usuarios_Todos'
}

function Usuarios-Inactivos {
    [CmdletBinding()]
    param()
    $dias = [int](Read-Host "Días de inactividad")
    if ($dias -lt 1) { Write-Warn "Valor inválido"; Pause; return }
    $fechaLimite = (Get-Date).AddDays(-$dias)
    # Nota: LastLogonDate viene de lastLogonTimestamp (aprox). Precisión suficiente para reportes operativos.
    $result = Get-ADUser -Filter * -Properties LastLogonDate,SamAccountName,DisplayName |
        Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $fechaLimite } |
        Select-Object @{Name='Name';Expression={$_.DisplayName}},SamAccountName,@{Name='LastLogon';Expression={$_.LastLogonDate}}
    if (-not $result -or $result.Count -eq 0) {
        Write-Host "No se encontraron usuarios inactivos"
        Pause
        return
    }
    $result | Sort-Object LastLogon | Format-Table -AutoSize
    $count = $result.Count
    Write-Host "Total usuarios inactivos: $count"
    Exportar-Resultados -Datos $result -Prefijo "Usuarios_Inactivos_${dias}d"
}

function Usuarios-Bloqueados {
    [CmdletBinding()]
    param()
    $result = Search-ADAccount -LockedOut -UsersOnly |
        Select-Object Name,SamAccountName
    if (-not $result -or $result.Count -eq 0) {
        Write-Host "No se encontraron usuarios bloqueados"
        Pause
        return
    }
    $result | Sort-Object Name | Format-Table -AutoSize
    $count = $result.Count
    Write-Host "Total usuarios bloqueados: $count"
    Exportar-Resultados -Datos $result -Prefijo 'Usuarios_Bloqueados'
}

function Usuarios-Deshabilitados {
    [CmdletBinding()]
    param()
    $result = Get-ADUser -Filter 'Enabled -eq $false' |
        Select-Object Name,SamAccountName
    if (-not $result -or $result.Count -eq 0) {
        Write-Host "No se encontraron usuarios deshabilitados"
        Pause
        return
    }
    $result | Sort-Object Name | Format-Table -AutoSize
    $count = $result.Count
    Write-Host "Total usuarios deshabilitados: $count"
    Exportar-Resultados -Datos $result -Prefijo 'Usuarios_Deshabilitados'
}

function Usuarios-PwdNeverExpires {
    [CmdletBinding()]
    param()
    $result = Get-ADUser -Filter 'PasswordNeverExpires -eq $true' |
        Select-Object Name,SamAccountName
    if (-not $result -or $result.Count -eq 0) {
        Write-Host "No se encontraron usuarios con pwd never expires"
        Pause
        return
    }
    $result | Sort-Object Name | Format-Table -AutoSize
    $count = $result.Count
    Write-Host "Total usuarios con pwd never expires: $count"
    Exportar-Resultados -Datos $result -Prefijo 'Usuarios_PwdNeverExpires'
}

function Usuarios-PwdExpirando {
    [CmdletBinding()]
    param()
    $dias = [int](Read-Host "Días hasta expiración")
    if ($dias -lt 1) { Write-Warn "Valor inválido"; Pause; return }
    # Formato requerido: D.HH:MM:SS (ej. 10.00:00:00)
    $ts = New-TimeSpan -Days $dias
    $tsString = "{0}.{1:00}:{2:00}:{3:00}" -f $ts.Days,$ts.Hours,$ts.Minutes,$ts.Seconds
    $result = Search-ADAccount -UsersOnly -PasswordExpiring -TimeSpan $tsString |
        Select-Object Name,SamAccountName,@{Name='ExpiryDays';Expression={$dias}}
    if (-not $result -or $result.Count -eq 0) {
        Write-Host "No se encontraron usuarios con pwd expirando en $dias días"
        Pause
        return
    }
    $result | Sort-Object Name | Format-Table -AutoSize
    $count = $result.Count
    Write-Host "Total usuarios con pwd expirando en $dias días: $count"
    Exportar-Resultados -Datos $result -Prefijo "Usuarios_PwdExpirando_${dias}d"
}

function Menu-Usuarios {
    while ($true) {
        Clear-Host
        Write-Host "--- Menu Usuarios ---"
        Write-Host "1. Listar todos los usuarios"
        Write-Host "2. Usuarios inactivos"
        Write-Host "3. Usuarios bloqueados"
        Write-Host "4. Usuarios deshabilitados"
        Write-Host "5. Usuarios pwd never expires"
        Write-Host "6. Usuarios pwd expiring"
        Write-Host "7. Volver"
        $opt = Read-Host "Selecciona una opcion"
        switch ($opt) {
            '1' { Listar-Usuarios }
            '2' { Usuarios-Inactivos }
            '3' { Usuarios-Bloqueados }
            '4' { Usuarios-Deshabilitados }
            '5' { Usuarios-PwdNeverExpires }
            '6' { Usuarios-PwdExpirando }
            '7' { return }
            default { Write-Host "Opcion no valida"; Pause }
        }
    }
}

# ---------- Funciones Equipos ----------
function Listar-Equipos {
    [CmdletBinding()]
    param()
    $result = Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate |
        Select-Object Name,OperatingSystem,@{Name='LastLogon';Expression={$_.LastLogonDate}}
    if (-not $result -or $result.Count -eq 0) {
        Write-Host "No se encontraron equipos"
        Pause
        return
    }
    $result | Sort-Object Name | Format-Table -AutoSize
    $count = $result.Count
    Write-Host "Total equipos encontrados: $count"
    Exportar-Resultados -Datos $result -Prefijo 'Equipos_Todos'
}

function Equipos-Inactivos {
    [CmdletBinding()]
    param()
    $dias = [int](Read-Host "Días de inactividad")
    if ($dias -lt 1) { Write-Warn "Valor inválido"; Pause; return }
    $fechaLimite = (Get-Date).AddDays(-$dias)
    $result = Get-ADComputer -Filter * -Properties LastLogonDate |
        Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $fechaLimite } |
        Select-Object Name,@{Name='LastLogon';Expression={$_.LastLogonDate}}
    if (-not $result -or $result.Count -eq 0) {
        Write-Host "No se encontraron equipos inactivos"
        Pause
        return
    }
    $result | Sort-Object LastLogon | Format-Table -AutoSize
    $count = $result.Count
    Write-Host "Total equipos inactivos: $count"
    Exportar-Resultados -Datos $result -Prefijo "Equipos_Inactivos_${dias}d"
}

function Equipos-PorOS {
    [CmdletBinding()]
    param()
    $result = Get-ADComputer -Filter * -Properties OperatingSystem |
        Group-Object OperatingSystem |
        Select-Object @{Name='OperatingSystem';Expression={$_.Name}},Count
    if (-not $result -or $result.Count -eq 0) {
        Write-Host "No se encontraron tipos de OS"
        Pause
        return
    }
    $result | Sort-Object OperatingSystem | Format-Table -AutoSize
    $count = $result.Count
    Write-Host "Total tipos de OS: $count"
    Exportar-Resultados -Datos $result -Prefijo 'Equipos_PorOS'
}

function Equipos-LargoUptime {
    [CmdletBinding()]
    param()
    $dias = [int](Read-Host "Días")
    if ($dias -lt 1) { Write-Warn "Valor inválido"; Pause; return }
    # AD no guarda uptime; usamos LastLogonDate como proxy aproximado
    $fechaLimite = (Get-Date).AddDays(-$dias)
    $result = Get-ADComputer -Filter * -Properties LastLogonDate |
        Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $fechaLimite } |
        Select-Object Name,@{Name='LastLogon';Expression={$_.LastLogonDate}}
    if (-not $result -or $result.Count -eq 0) {
        Write-Host "No se encontraron equipos sin reinicio > $dias dias"
        Pause
        return
    }
    $result | Sort-Object LastLogon | Format-Table -AutoSize
    $count = $result.Count
    Write-Host "Total equipos sin reinicio > $dias dias: $count"
    Exportar-Resultados -Datos $result -Prefijo "Equipos_LargoUptime_${dias}d"
}

function Equipos-Offline {
    [CmdletBinding()]
    param()
    $names = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
    $offline = foreach ($n in $names) {
        try {
            # Timeout razonable por host; -Quiet devuelve bool
            if (-not (Test-Connection -ComputerName $n -Count 1 -Quiet -TimeoutSeconds 1)) {
                [PSCustomObject]@{ Name = $n }
            }
        } catch {
            [PSCustomObject]@{ Name = $n }
        }
    }
    if (-not $offline -or $offline.Count -eq 0) {
        Write-Host "No se encontraron equipos offline"
        Pause
        return
    }
    $offline | Sort-Object Name | Format-Table -AutoSize
    $count = $offline.Count
    Write-Host "Total equipos offline: $count"
    Exportar-Resultados -Datos $offline -Prefijo 'Equipos_Offline'
}

function Equipos-EnOU {
    [CmdletBinding()]
    param()
    $ou = Read-Host "DistinguishedName de la OU"
    if (-not $ou) { Write-Warn "OU inválida"; Pause; return }
    $result = Get-ADComputer -SearchBase $ou -Filter * |
        Select-Object Name
    if (-not $result -or $result.Count -eq 0) {
        Write-Host "No se encontraron equipos en OU"
        Pause
        return
    }
    $result | Sort-Object Name | Format-Table -AutoSize
    $count = $result.Count
    Write-Host "Total equipos en OU: $count"
    Exportar-Resultados -Datos $result -Prefijo 'Equipos_EnOU'
}

# ---------- Menús ----------
function Menu-Equipos {
    while ($true) {
        Clear-Host
        Write-Host "--- Menu Equipos ---"
        Write-Host "1. Listar todos los equipos"
        Write-Host "2. Equipos inactivos"
        Write-Host "3. Equipos por OS"
        Write-Host "4. Equipos sin reinicio (uptime)"
        Write-Host "5. Equipos offline"
        Write-Host "6. Equipos en OU"
        Write-Host "7. Volver"
        $opt = Read-Host "Selecciona una opcion"
        switch ($opt) {
            '1' { Listar-Equipos }
            '2' { Equipos-Inactivos }
            '3' { Equipos-PorOS }
            '4' { Equipos-LargoUptime }
            '5' { Equipos-Offline }
            '6' { Equipos-EnOU }
            '7' { return }
            default { Write-Host "Opcion no valida"; Pause }
        }
    }
}

# Menu principal
while ($true) {
    Clear-Host
    Write-Host "========================="
    Write-Host "GESTOR DE AD - USUARIOS Y EQUIPOS"
    Write-Host "========================="
    Write-Host "1. Usuarios"
    Write-Host "2. Equipos"
    Write-Host "3. Salir"
    $main = Read-Host "Selecciona una opcion"
    switch ($main) {
        '1' { Menu-Usuarios }
        '2' { Menu-Equipos }
        '3' { Write-Host "Saliendo..."; exit }
        default { Write-Host "Opcion no valida"; Pause }
    }
}
