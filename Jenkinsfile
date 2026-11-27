// Jenkinsfile - Pipeline de "Sistema Alumnos" (SecureDev · Evaluación Parcial 3 · OCY1102)
//
// Etapas: Build -> Test -> Security Review (SAST) -> Dependency Management -> Deploy Producción.
// Los marcadores  >>> [ETIQUETA]  indican dónde se agregarán las etapas siguientes.
pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 40, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    // Revisa GitHub cada ~3 minutos: cada push (tuyo o un PR de Dependabot fusionado) dispara un build.
    triggers {
        pollSCM('H/3 * * * *')
    }

    environment {
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
    }

    stages {
        stage('Build') {
            steps {
                script {
                    // Versión = 1.0.<nº de build>+<commit corto>: une cada despliegue con su commit (trazabilidad)
                    def sha = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    env.APP_VERSION = "1.0.${env.BUILD_NUMBER}+${sha}"
                }
                echo "Versión de este build: ${env.APP_VERSION}"
                sh 'git log -1 --format="Commit %h de %an: %s"'
                // Cada build parte limpio: sin reportes viejos y con un entorno virtual nuevo
                sh 'rm -rf .venv reports && mkdir -p reports'
                sh 'python3 -m venv .venv'
                sh '.venv/bin/pip install --quiet -r requirements.txt -r requirements-dev.txt'
                sh '.venv/bin/python -m compileall -q app.py'
            }
        }

        stage('Test') {
            steps {
                sh '.venv/bin/python -m pytest --junitxml=reports/junit.xml'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/junit.xml'
                }
            }
        }

        // Revisión de seguridad continua del CÓDIGO (SAST) con Bandit
        stage('Security Review (SAST)') {
            steps {
                // Reportes completos (todas las severidades) para la trazabilidad
                sh 'bandit -r app.py -f json -o reports/bandit.json || true'
                sh 'bandit -r app.py -f txt -o reports/bandit.txt || true'
                sh 'cat reports/bandit.txt'
                // Si hay hallazgos Medium o High, el build queda UNSTABLE (amarillo)
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh 'bandit -q -ll -r app.py'
                }
            }
        }

        // Gestión de DEPENDENCIAS (SCA) con pip-audit
        stage('Dependency Management') {
            steps {
                sh 'pip-audit -r requirements.txt -f json -o reports/pip-audit.json || true'
                sh 'pip-audit -r requirements.txt -o reports/pip-audit.txt || true'
                sh 'cat reports/pip-audit.txt'
                // Si hay dependencias con vulnerabilidades conocidas, el build queda UNSTABLE
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh 'pip-audit -r requirements.txt'
                }
            }
        }

        // Se despliega una copia en STAGING (puerto 5001) para atacarla con ZAP sin tocar producción
        stage('Deploy Staging') {
            steps {
                sh 'bash scripts/deploy.sh staging 5001'
            }
        }

        // Pruebas dinámicas (DAST) con OWASP ZAP: spider + escaneo pasivo + escaneo activo
        stage('DAST - OWASP ZAP') {
            steps {
                // ZAP corre en su propio contenedor y alcanza la app de staging por la red interna
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh 'python3 scripts/zap_scan.py http://jenkins:5001'
                }
            }
        }

        stage('Deploy Producción') {
            // >>> [GATE]: aquí va la condición "when" que protege producción
            steps {
                sh 'bash scripts/deploy.sh produccion 5000'
                script { env.PRODUCCION = env.APP_VERSION }
            }
        }
    }

    post {
        always {
            // Registro de trazabilidad: build <-> versión <-> commit <-> pruebas <-> hallazgos <-> despliegue
            withEnv(["RESULTADO=${currentBuild.currentResult}"]) {
                sh 'python3 scripts/trazabilidad.py'
            }
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
    }
}