@Library('p1pipeline')_
  
pipeline {
    options {
        buildDiscarder(logRotator(numToKeepStr:'10'))
        timeout(time: 10, unit: 'MINUTES')
    }

    environment {
        CI_REGISTRY_IMAGE = "p1hub/auth1"
        P1_PROJECT = "p1auth1"
    }

    agent any
    stages {
        stage('Build') {
            steps {
                script {
                    p1build()
                }
            }
        }

        stage('Tests') {
            agent {
                docker { image 'golang:1.11-alpine' }
            }
            environment {
                XDG_CACHE_HOME = "/tmp/.cache"
                GO111MODULE = "on"
            }
            steps {
                sh "apk update && apk add git"
                sh "go test ./... -coverprofile=coverage.out -covermode=atomic -p=1"
            }
        }

        stage('Staging Deployment') {
            steps {
                script {
                    p1deploy()
                }
            }
        }
    }
    post {
        success {
            slackSend (color: '#00FF00', message: "SUCCESSFUL: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL})")
        }
        
        failure {
            slackSend (color: '#FF0000', message: "FAILED: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL})")
        }
    }
}
