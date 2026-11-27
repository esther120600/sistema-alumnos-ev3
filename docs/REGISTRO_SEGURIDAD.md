# Registro de seguridad · Sistema Alumnos

Estudiante: Esther Orellana   Repositorio: https://github.com/esther120600/sistema-alumnos-ev3   Fecha: 27-11-2026

Cada fila puede seguirse hasta un **build de Jenkins** y un **commit** (el mensaje del commit lleva el identificador `VULN-xx`).

## 1. Revisiones de seguridad realizadas

| # | Etapa del SDLC | Herramienta / técnica | Build | Resultado (resumen) |
|---|---|---|---|---|
| R1 | Código (SAST) | Bandit 1.8.6 en el pipeline | #2 (antes) · #5 (después) | Antes: 2 High / 2 Medium / 1 Low. Después de corregir VULN-01..07: 0 / 0 / 0 |
| R2 | Dependencias (SCA) | pip-audit 2.9.0 en el pipeline | #2 (antes) · #10 y #11 (después) | Antes: 19 vulnerabilidades en 4 paquetes (flask, werkzeug, jinja2, gunicorn). Después: 0 |
| R3 | Pruebas dinámicas (DAST) | OWASP ZAP 2.16.1 sobre staging (:5001) | #4 (antes) · #5 y #11 (después) | Antes: 2 High / 3 Medium / 1 Low. Después: 0 High / 0 Medium / 0 Low (solo 2 informativas) |
| R4 | Revisión manual | Lectura de `app.py` | — | Se identificaron 8 vulnerabilidades (VULN-01 a VULN-08); el XSS de `/hello` y la falta de protección en `/login` no los detecta Bandit |
| R5 | Producción | Grafana 11.4 + Prometheus 2.54 | — | Dashboard "Producción · Sistema Alumnos" y regla de alerta "Fuerza bruta en login (producción)" (más de 3 logins fallidos por minuto) |

## 2. Vulnerabilidades identificadas y corregidas

| ID | Vulnerabilidad (CWE) | Detectada por | Ubicación | Riesgo | Corrección aplicada | Commit | Build que lo verifica |
|---|---|---|---|---|---|---|---|
| VULN-01 | Inyección SQL en `/alumnos/buscar` (CWE-89) | Bandit B608 y revisión manual | `app.py:205` | Medio (alto por impacto) | Consulta parametrizada `LIKE ?` con parámetro | `83b0fdd` | #3 (Bandit sin B608) |
| VULN-02 | XSS reflejado en `/hello` (CWE-79) | ZAP (2 alertas High) y revisión manual | `app.py` ruta `/hello` | Alto | `render_template_string` con autoescape (`{{ name }}`) | `ff1bd6b` | #5 (ZAP sin XSS) |
| VULN-03 | MD5 sin sal para la clave del admin (CWE-327) | Bandit B324 | `app.py:221` | Alto | `check_password_hash` / `generate_password_hash` (werkzeug), hash por variable de entorno | `372719e` | #5 |
| VULN-04 | Secretos en el código: SECRET_KEY y usuario admin (CWE-259/798) | Bandit B105 | `app.py:20` | Bajo/Medio | `SECRET_KEY` y usuario desde variables de entorno (o clave aleatoria) | `36e1508` | #5 |
| VULN-05 | `debug=True` y escucha en `0.0.0.0` (CWE-489/605) | Bandit B201 y B104 | `app.py:241` | Alto | Debug solo con `FLASK_DEBUG=1`; escucha en `127.0.0.1` | `515f2a2` | #5 |
| VULN-06 | Fuerza bruta y falta de token CSRF en `/login` (CWE-307/352) | ZAP (Absence of Anti-CSRF Tokens) y revisión manual | `app.py` ruta `/login` | Medio | Token CSRF en sesión (`hmac.compare_digest`), límite de 5 fallos por 60 s con HTTP 429, cookie HttpOnly/SameSite | `b47cf26` | #5 y simulación de ataque (26 de 31 intentos bloqueados) |
| VULN-07 | Sin cabeceras de seguridad HTTP (CWE-693/1021) | ZAP (CSP, anti-clickjacking, nosniff) | `app.py` (`after_request`) | Medio | CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP, Cache-Control | `35523a5` | #5 |
| VULN-08 | Error SQL expone la consulta (CWE-209) | Revisión manual | `app.py:209` | Medio | Error genérico y registro interno con `logger.exception` (se corrigió junto con VULN-01) | `83b0fdd` | #3 |

## 3. Resultados de OWASP ZAP

Escaneo sobre staging (`http://jenkins:5001`), build #4 (código vulnerable): High 2, Medium 3, Low 1, Informational 0.

| Alerta de ZAP | Riesgo | URL de ejemplo | VULN relacionada | Cómo se mitiga | ¿Mitigada? Build |
|---|---|---|---|---|---|
| Cross Site Scripting (DOM Based) | High | `/hello?name=<script>alert(5397)</script>` | VULN-02 | Autoescape de la plantilla | Sí · #5 |
| Cross Site Scripting (Reflected) | High | `/hello?name=</h1><scrIpt>alert(1);</scRipt><h1>` | VULN-02 | Autoescape de la plantilla | Sí · #5 |
| Absence of Anti-CSRF Tokens | Medium | `http://jenkins:5001/` (formulario de `/login`) | VULN-06 | Token `csrf_token` en sesión y campo oculto | Sí · #5 |
| Content Security Policy (CSP) Header Not Set | Medium | `/`, `/hello?name=Ana`, `/robots.txt` | VULN-07 | Cabecera `Content-Security-Policy` | Sí · #5 |
| Missing Anti-clickjacking Header | Medium | `/`, `/hello?name=Ana` | VULN-07 | `X-Frame-Options: DENY` y `frame-ancestors 'none'` | Sí · #5 |
| X-Content-Type-Options Header Missing | Low | `/`, `/alumnos`, `/alumnos/buscar?nombre=Ana` | VULN-07 | `X-Content-Type-Options: nosniff` | Sí · #5 |

Resultado tras las correcciones (build #5): High 0, Medium 0, Low 0, Informational 2 (Session Management Response Identified y User Agent Fuzzer, informativas).

## 4. Monitoreo e incidentes

Monitoreo de producción (`http://jenkins:5000`, versión `1.0.5+35523a5`): dashboard "Producción · Sistema Alumnos" en Grafana, datos de Prometheus (job `produccion`, cada 5 s). Regla de alerta "Fuerza bruta en login (producción)": se dispara si `sum(increase(login_fallidos_total{job="produccion"}[1m]))` es mayor que 3, evaluada cada 10 s, severidad alta.

| Hora | Panel / métrica de Grafana | Qué se observó | Entorno | Clasificación | Acción de respuesta | Verificación |
|---|---|---|---|---|---|---|
| 17:54 (27-11-2026) | Logins fallidos (último minuto) y Peticiones sospechosas (último minuto) | Logins fallidos 5,45 y peticiones sospechosas 30,5 (tipos fuerza_bruta, sqli y xss); aparecen respuestas HTTP 401 y 429; la regla pasa a **Firing** | Producción | Intento de fuerza bruta en `/login` con pruebas de inyección SQL y XSS · severidad alta | Bloqueo automático por el límite de intentos (VULN-06): HTTP 429 tras 5 fallos en 60 s; la SQLi y el XSS ya estaban mitigados (VULN-01, VULN-02) | Simulación: 31 intentos de login, ninguna clave funcionó y 26 fueron bloqueados (429); la inyección SQL no devolvió datos y el script XSS se escapó; el contador volvió a 0 y el build #11 quedó en verde |

**Detección.** La métrica `login_fallidos_total` superó el umbral y la regla de Grafana pasó a Firing.

**Análisis.** Los contadores `peticiones_sospechosas_total{tipo}` mostraron tres tipos de intento: `fuerza_bruta`, `sqli` y `xss`. Los intentos llegaron en ráfaga.

**Clasificación.** Ataque de autenticación (fuerza bruta) acompañado de pruebas de inyección; severidad alta; ningún acceso obtenido.

**Respuesta.** El límite de intentos (HTTP 429) bloqueó el ataque y las correcciones VULN-01 y VULN-02 neutralizaron los otros dos intentos.

**Verificación.** Respuestas 429 visibles en el panel de peticiones por código HTTP, contadores de vuelta a 0 al terminar y pipeline final en verde (build #11).

## 5. Gestión de dependencias

Dependabot (`.github/dependabot.yml`, ecosistema pip, revisión diaria) y Dependabot security updates abrieron 6 pull requests. Dependabot alerts mostró 20 alertas abiertas (5 High, 13 Moderate, 2 Low) antes de los merges.

| Paquete | Versión inicial | Vulnerabilidades (IDs) | Versión final | Origen del cambio (PR de Dependabot / manual) | ¿Pruebas, pip-audit y ZAP siguen OK? Build |
|---|---|---|---|---|---|
| Flask | 2.2.2 | PYSEC-2023-62, PYSEC-2026-2151 | 3.1.3 | PR #4 de Dependabot | Sí · #8 (7 vuln. restantes), luego 0 en #10 y #11 |
| Werkzeug | 2.2.2 | PYSEC-2023-58, 2023-57, 2023-221, 2026-2046, 2026-2045, 2026-2044, 2026-2043, 2026-2320, 2026-3417, 2026-4312 | 3.1.9 | PR #2 de Dependabot | #7 falló (Werkzeug 3 es incompatible con Flask 2.2.2, error esperado en un merge intermedio); se resolvió al mergear Flask 3.1.3 (#8) |
| Jinja2 | 3.1.2 | PYSEC-2026-1473, 1471, 1474, 1475, 1472 | 3.1.6 | PR #5 de Dependabot | Sí · #10 y #11 |
| gunicorn | 21.2.0 | PYSEC-2026-1434, 1433 | 27.0.1 | PR #1 de Dependabot | Sí · #9 (5 vuln. restantes), luego 0 en #10 y #11 |
| prometheus-client | 0.17.1 | ninguna | 0.26.0 | PR #3 de Dependabot | Sí · #10 y #11 |
| pytest (desarrollo) | 8.3.4 | 1 alerta Moderate (tmpdir) | 9.2.0 | PR #6 de Dependabot | Sí · #10 y #11 (9 pruebas OK) |

**Evolución de pip-audit:** 19 vulnerabilidades (build #2 a #6) → 7 (#8, tras Werkzeug y Flask) → 5 (#9, tras gunicorn) → 0 (#10 y #11, tras Jinja2, prometheus-client y pytest).

**Incidente del build #10.** Falló la etapa Dependency Management porque, sin vulnerabilidades, pip-audit no crea `pip-audit.txt` y el pipeline intentaba leerlo. Se corrigió en el `Jenkinsfile` (commit `25298a3`) y se agregó la condición `when` que despliega a producción solo si el pipeline queda en verde. El build #11 quedó SUCCESS.

## 6. Trazabilidad

`TRAZABILIDAD.md` del build #11 (generado por `scripts/trazabilidad.py` al terminar cada build):

| Build | Fecha (UTC) | Versión | Commit | Mensaje del commit | Pruebas | Bandit H/M/L | pip-audit | ZAP H/M/L | Resultado | Producción |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 2026-11-27 19:45 | 1.0.1+d40ccc1 | `d40ccc1` | Código base vulnerable entregado por el profesor | 9/9 OK | n/a | n/a | n/a | SUCCESS | 1.0.1+d40ccc1 |
| 2 | 2026-11-27 19:52 | 1.0.2+d5537e3 | `d5537e3` | Pipeline: agrega Security Review (Bandit) y Dependency Management (pip-audit) | 9/9 OK | 2/2/1 | 19 vuln. | n/a | UNSTABLE | 1.0.2+d5537e3 |
| 3 | 2026-11-27 20:08 | 1.0.3+83b0fdd | `83b0fdd` | VULN-01: consulta parametrizada en /alumnos/buscar | 9/9 OK | 2/1/1 | 19 vuln. | n/a | UNSTABLE | 1.0.3+83b0fdd |
| 4 | 2026-11-27 20:20 | 1.0.4+b71f09f | `b71f09f` | Pipeline: agrega Deploy Staging y DAST con OWASP ZAP | 9/9 OK | 2/1/1 | 19 vuln. | 2/3/1 | UNSTABLE | 1.0.4+b71f09f |
| 5 | 2026-11-27 20:36 | 1.0.5+35523a5 | `35523a5` | VULN-07: cabeceras de seguridad HTTP en todas las respuestas | 9/9 OK | 0/0/0 | 19 vuln. | 0/0/0 | UNSTABLE | 1.0.5+35523a5 |
| 6 | 2026-11-27 21:07 | 1.0.6+0085afe | `0085afe` | Agregar dependabot.yml para actualizar dependencias pip | 9/9 OK | 0/0/0 | 19 vuln. | 0/0/0 | UNSTABLE | 1.0.6+0085afe |
| 7 | 2026-11-27 21:11 | 1.0.7+c213d6c | `c213d6c` | Merge pull request #2 (werkzeug 3.1.9) | 0/1 OK | n/a | n/a | n/a | FAILURE | no desplegado |
| 8 | 2026-11-27 21:15 | 1.0.8+e2c1753 | `e2c1753` | Merge pull request #4 (flask 3.1.3) | 9/9 OK | 0/0/0 | 7 vuln. | 0/0/0 | UNSTABLE | 1.0.8+e2c1753 |
| 9 | 2026-11-27 21:19 | 1.0.9+9e72139 | `9e72139` | Merge pull request #1 (gunicorn 27.0.1) | 9/9 OK | 0/0/0 | 5 vuln. | 0/0/0 | UNSTABLE | 1.0.9+9e72139 |
| 10 | 2026-11-27 21:20 | 1.0.10+397920f | `397920f` | Merge pull request #6 (pytest 9.2.0) | 9/9 OK | 0/0/0 | 0 vuln. | n/a | FAILURE | no desplegado |
| 11 | 2026-11-27 21:27 | 1.0.11+25298a3 | `25298a3` | Jenkinsfile: reporte pip-audit sin vulnerabilidades y gate de producción | 9/9 OK | 0/0/0 | 0 vuln. | 0/0/0 | SUCCESS | 1.0.11+25298a3 |

Recorrido por cada actividad del pipeline:

| Actividad | Hallazgo | Build que lo detectó | Commit / PR que lo resolvió | Build que lo verificó | Versión en producción |
|---|---|---|---|---|---|
| Revisión de seguridad (Bandit) | B608, B324, B201, B104, B105 (5 hallazgos) | #2 | `83b0fdd`, `372719e`, `36e1508`, `515f2a2` | #3 y #5 | 1.0.5+35523a5 |
| Prueba automatizada (OWASP ZAP) | XSS (2), sin token CSRF, sin CSP, sin anti-clickjacking, sin nosniff | #4 | `ff1bd6b`, `b47cf26`, `35523a5` | #5 y #11 | 1.0.11+25298a3 |
| Gestión de dependencias (Dependabot) | 19 vulnerabilidades en flask, werkzeug, jinja2 y gunicorn | #2 | PR #2, #4, #5, #1, #3 y #6 | #11 | 1.0.11+25298a3 |
