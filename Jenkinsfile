pipeline {
    agent any
 
    environment {
        IMAGE_NAME = "tommy6769/levigametest"
        TRIVY_SEVERITY = "HIGH,CRITICAL"
    }
 
    stages {
 
        stage("Check Docker Availability") {
            steps {
                script {
                    echo 'Checking Docker installation...'
                    def dockerCheck = sh(script: 'which docker', returnStatus: true)
                    if (dockerCheck != 0) {
                        error "Docker command not found! Please install Docker or mount /var/run/docker.sock."
                    }
                    sh 'docker --version'
                }
            }
        }
 
        stage("Pull Target Container Image") {
            steps {
                script {
                    echo "Pulling image: ${IMAGE_NAME}"
                    sh "docker pull ${IMAGE_NAME}"
                }
            }
        }
 
        stage("Container Vulnerability Scan (Trivy)") {
            steps {
                script {
                    echo "Scanning Docker image ${IMAGE_NAME} for vulnerabilities..."
 
                    // JSON report
                    sh """
                        docker run --rm -v \$(pwd):/workspace aquasec/trivy:latest image \
                        --exit-code 0 \
                        --format json \
                        --output /workspace/trivy-report.json \
                        --severity ${TRIVY_SEVERITY} \
                        ${IMAGE_NAME}
                    """
 
                    // HTML report
                    sh """
                        docker run --rm -v \$(pwd):/workspace aquasec/trivy:latest image \
                        --exit-code 0 \
                        --format template \
                        --template "@/contrib/html.tpl" \
                        --output /workspace/trivy-report.html \
                        ${IMAGE_NAME}
                    """
                }
            }
            post {
                always {
                    echo "Archiving Trivy reports..."
                    archiveArtifacts artifacts: 'trivy-report.json,trivy-report.html', allowEmptyArchive: true
                }
            }
        }
 
        stage("Summarize Vulnerabilities") {
            steps {
                script {
                    if (fileExists('trivy-report.json')) {
                        def reportContent = readFile('trivy-report.json')
                        def reportJson = new groovy.json.JsonSlurper().parseText(reportContent)
 
                        def highCount = 0
                        def criticalCount = 0
 
                        reportJson.Results.each { result ->
                            result.Vulnerabilities?.each { vuln ->
                                switch (vuln.Severity) {
                                    case 'HIGH': highCount++; break
                                    case 'CRITICAL': criticalCount++; break
                                }
                            }
                        }
 
                        echo "HIGH vulnerabilities: ${highCount}"
                        echo " CRITICAL vulnerabilities: ${criticalCount}"
 
                        if (criticalCount > 0) {
                            error "Critical vulnerabilities detected: ${criticalCount}"
                        }
                    } else {
                        echo "Trivy JSON report not found!"
                    }
                }
            }
        }
    }
 
    post {
        always {
            echo 'Container Security Scan completed.'
 
            // Publish HTML report in Jenkins UI
            publishHTML([
                reportDir: '.',
                reportFiles: 'trivy-report.html',
                reportName: 'Trivy Vulnerability Report',
                keepAll: true,
                alwaysLinkToLastBuild: true,
                allowMissing: true
            ])
        }
    }
}
