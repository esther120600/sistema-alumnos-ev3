"""!
@file app.py
@brief "Sistema Alumnos" de SecureDev: API y portal web de alumnos (Evaluación Parcial 3, OCY1102).

Además de las rutas de negocio, la app publica métricas para Prometheus en /metrics.
Las métricas de seguridad (logins fallidos y peticiones sospechosas) se ven en Grafana.
"""
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time

from flask import Flask, Response, g, jsonify, render_template_string, request, session
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

## Clave de la aplicación y credenciales del administrador.
## La clave de sesión viene del entorno; si falta, se genera una aleatoria al iniciar (despliegue con 1 worker).
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
ADMIN_USUARIO = os.environ.get("ADMIN_USUARIO", "admin")
## Hash con sal de la clave del administrador (se entrega por la variable de entorno ADMIN_CLAVE_HASH).
## Si no se define, se genera una clave aleatoria que nadie conoce: el acceso de administrador queda cerrado.
ADMIN_CLAVE_HASH = os.environ.get("ADMIN_CLAVE_HASH") or generate_password_hash(secrets.token_urlsafe(24))
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

## Límite de intentos de login fallidos por dirección (frena la fuerza bruta).
LIMITE_INTENTOS = 5
VENTANA_SEGUNDOS = 60
INTENTOS_FALLIDOS = {}
CANDADO_INTENTOS = threading.Lock()

## Versión desplegada: la inyecta el pipeline (1.0.<build>+<commit>). Sirve para la trazabilidad.
VERSION = os.environ.get("APP_VERSION", "dev")
## Archivo SQLite con los alumnos (cada entorno usa el suyo).
DB_PATH = os.environ.get("DB_PATH", "alumnos.db")

ALUMNOS_INICIALES = [
    (1, "Ana Pérez", "Ingeniería en Informática", 6.1),
    (2, "Benjamín Rojas", "Ingeniería en Ciberseguridad", 5.4),
    (3, "Camila Soto", "Analista Programador", 6.8),
    (4, "Diego Muñoz", "Ingeniería en Informática", 4.9),
]

# ---------------------------------------------------------------- métricas (no modificar los nombres)
HTTP_PETICIONES = Counter("http_requests_total", "Peticiones HTTP atendidas", ["method", "endpoint", "status"])
HTTP_LATENCIA = Histogram("http_request_duration_seconds", "Duración de las peticiones HTTP", ["endpoint"])
LOGIN_FALLIDOS = Counter("login_fallidos_total", "Intentos de inicio de sesión fallidos")
LOGIN_EXITOSOS = Counter("login_exitosos_total", "Inicios de sesión correctos")
SOSPECHOSAS = Counter("peticiones_sospechosas_total", "Peticiones con patrones de ataque", ["tipo"])
APP_INFO = Gauge("app_info", "Versión desplegada de la aplicación", ["version"])
APP_INFO.labels(version=VERSION).set(1)

## Patrones que delatan un intento de ataque (detección, no bloqueo).
PATRONES_ATAQUE = {
    "xss": re.compile(r"<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img", re.I),
    "sqli": re.compile(r"('|%27)\s*(or|and|union)\b|union\s+select|--|;\s*drop\b|sleep\(", re.I),
    "path_traversal": re.compile(r"\.\./|\.\.\\|%2e%2e", re.I),
}

## Cabeceras de seguridad que se agregan a todas las respuestas.
CABECERAS_SEGURIDAD = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}

PORTADA = """<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>Sistema Alumnos</title></head>
<body>
<h1>Sistema Alumnos · SecureDev</h1>
<p>Versión {{ version }}</p>
<ul>
  <li><a href="/alumnos">Listado de alumnos (JSON)</a></li>
  <li><a href="/alumnos/1">Alumno 1</a></li>
  <li><a href="/hello?name=Ana">Saludo</a></li>
</ul>
<h2>Buscar alumno</h2>
<form action="/alumnos/buscar" method="get">
  <input name="nombre" value="Ana"> <button type="submit">Buscar</button>
</form>
<h2>Acceso administrador</h2>
<form action="/login" method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input name="usuario" value="admin"> <input name="clave" type="password" value="">
  <button type="submit">Entrar</button>
</form>
</body>
</html>"""


def conectar():
    """!
    @brief Abre (una vez por petición) la conexión a la base de datos SQLite.
    @return Conexión sqlite3 con filas accesibles por nombre de columna.
    """
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(_error):
    """!
    @brief Cierra la conexión a la base de datos al terminar cada petición.
    @param _error Excepción de la petición (si la hubo); no se usa.
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


def iniciar_db():
    """!
    @brief Crea la tabla de alumnos y carga los datos iniciales si está vacía.
    """
    db = sqlite3.connect(DB_PATH)
    db.execute("CREATE TABLE IF NOT EXISTS alumnos (id INTEGER PRIMARY KEY, nombre TEXT, carrera TEXT, promedio REAL)")
    if db.execute("SELECT COUNT(*) FROM alumnos").fetchone()[0] == 0:
        db.executemany("INSERT INTO alumnos VALUES (?, ?, ?, ?)", ALUMNOS_INICIALES)
    db.commit()
    db.close()


@app.before_request
def antes_de_la_peticion():
    """!
    @brief Marca el inicio de la petición y cuenta los parámetros con patrones de ataque.
    """
    g.inicio = time.perf_counter()
    valores = list(request.args.values()) + list(request.form.values())
    for tipo, patron in PATRONES_ATAQUE.items():
        if any(patron.search(v) for v in valores):
            SOSPECHOSAS.labels(tipo=tipo).inc()
            app.logger.warning("Petición sospechosa (%s) desde %s a %s", tipo, request.remote_addr, request.path)


@app.after_request
def despues_de_la_peticion(respuesta):
    """!
    @brief Registra la métrica de cada petición atendida.
    @param respuesta Respuesta que Flask enviará al cliente.
    @return La misma respuesta.
    """
    endpoint = request.url_rule.rule if request.url_rule else "desconocido"
    if endpoint != "/metrics":
        HTTP_PETICIONES.labels(request.method, endpoint, str(respuesta.status_code)).inc()
        HTTP_LATENCIA.labels(endpoint).observe(time.perf_counter() - g.get("inicio", time.perf_counter()))
    for nombre, valor in CABECERAS_SEGURIDAD.items():
        respuesta.headers[nombre] = valor
    return respuesta


@app.route("/")
def portada():
    """!
    @brief Portada HTML con enlaces y formularios del sistema.
    @return Página HTML.
    """
    # Token anti-CSRF ligado a la sesión del navegador; /login lo exige
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return render_template_string(PORTADA, version=VERSION, csrf_token=session["csrf"])


@app.route("/hello")
def hello():
    """!
    @brief Saluda al usuario cuyo nombre llega en el parámetro de URL «name».
    @return Página HTML con el saludo.
    """
    name = request.args.get("name", "visitante")
    # La plantilla escapa el texto del usuario (autoescape), así <script> se muestra como texto
    return render_template_string("<h1>Hola, {{ name }}!</h1>", name=name)


@app.route("/health")
def health():
    """!
    @brief Estado de la aplicación (lo usan el despliegue y el monitoreo).
    @return JSON {"estado": "ok"}.
    """
    return jsonify({"estado": "ok"})


@app.route("/version")
def version():
    """!
    @brief Versión desplegada, para la trazabilidad.
    @return JSON con el nombre y la versión de la aplicación.
    """
    return jsonify({"aplicacion": "Sistema Alumnos", "version": VERSION})


@app.route("/alumnos")
def listar_alumnos():
    """!
    @brief Lista todos los alumnos.
    @return JSON con la lista de alumnos.
    """
    filas = conectar().execute("SELECT * FROM alumnos ORDER BY id").fetchall()
    return jsonify([dict(f) for f in filas])


@app.route("/alumnos/<int:alumno_id>")
def obtener_alumno(alumno_id):
    """!
    @brief Obtiene un alumno por su identificador.
    @param alumno_id Identificador numérico del alumno.
    @return JSON con el alumno, o error 404 si no existe.
    """
    fila = conectar().execute("SELECT * FROM alumnos WHERE id = ?", (alumno_id,)).fetchone()
    if fila is None:
        return jsonify({"error": "Alumno no encontrado"}), 404
    return jsonify(dict(fila))


@app.route("/alumnos/buscar")
def buscar_alumnos():
    """!
    @brief Busca alumnos cuyo nombre contenga el texto del parámetro «nombre».
    @return JSON con los alumnos encontrados.
    """
    nombre = request.args.get("nombre", "")
    try:
        # Consulta parametrizada: el texto del usuario nunca se concatena en el SQL
        filas = conectar().execute(
            "SELECT * FROM alumnos WHERE nombre LIKE ?", (f"%{nombre}%",)
        ).fetchall()
    except sqlite3.Error:
        # No se devuelve el detalle del error ni la consulta (evita filtrar información interna)
        app.logger.exception("Error al buscar alumnos")
        return jsonify({"error": "No se pudo completar la búsqueda"}), 500
    return jsonify([dict(f) for f in filas])


def demasiados_intentos(ip):
    """!
    @brief Indica si una dirección superó el límite de logins fallidos en la ventana de tiempo.
    @param ip Dirección del cliente.
    @return True si debe bloquearse temporalmente.
    """
    ahora = time.monotonic()
    with CANDADO_INTENTOS:
        recientes = [t for t in INTENTOS_FALLIDOS.get(ip, []) if ahora - t < VENTANA_SEGUNDOS]
        INTENTOS_FALLIDOS[ip] = recientes
        return len(recientes) >= LIMITE_INTENTOS


def registrar_fallo(ip):
    """!
    @brief Anota un login fallido de la dirección.
    @param ip Dirección del cliente.
    """
    with CANDADO_INTENTOS:
        INTENTOS_FALLIDOS.setdefault(ip, []).append(time.monotonic())


@app.route("/login", methods=["POST"])
def login():
    """!
    @brief Valida las credenciales del administrador enviadas por formulario.
    @return JSON con el resultado; 401 si las credenciales no son válidas.
    """
    ip = request.remote_addr
    if demasiados_intentos(ip):
        SOSPECHOSAS.labels(tipo="fuerza_bruta").inc()
        app.logger.warning("Login bloqueado por demasiados intentos desde %s", ip)
        return jsonify({"error": "Demasiados intentos. Espera un minuto."}), 429
    if not hmac.compare_digest(session.get("csrf", "").encode(), request.form.get("csrf_token", "").encode()):
        return jsonify({"error": "Solicitud no válida"}), 400
    usuario = request.form.get("usuario", "")
    clave = request.form.get("clave", "")
    if usuario == ADMIN_USUARIO and check_password_hash(ADMIN_CLAVE_HASH, clave):
        LOGIN_EXITOSOS.inc()
        return jsonify({"mensaje": "Bienvenido, administrador"})
    registrar_fallo(ip)
    LOGIN_FALLIDOS.inc()
    app.logger.warning("Login fallido para el usuario '%s' desde %s", usuario, request.remote_addr)
    return jsonify({"error": "Credenciales inválidas"}), 401


@app.route("/metrics")
def metrics():
    """!
    @brief Métricas en formato Prometheus.
    @return Texto con las métricas.
    """
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


iniciar_db()

if __name__ == "__main__":
    # Solo para desarrollo local: depurador apagado salvo FLASK_DEBUG=1 y solo escucha en la máquina local.
    # En los despliegues la app la sirve gunicorn (scripts/deploy.sh).
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
