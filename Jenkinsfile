@Library('p1pipeline')_
  
pipeline {
    options {
        buildDiscarder(logRotator(numToKeepStr:'10'))
        timeout(time: 10, unit: 'MINUTES')
    }

    environment {
        CI_REGISTRY_IMAGE = "p1hub/${registry}"
        P1_PROJECT = "${project}"
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

/*        stage('Run Tests') {
            parallel {
                stage('Test 1') {
                    steps {
                        sh "sleep 5"
                    }
                }
                stage('Test 2') {
                    steps {
                        sh "sleep 5"
                    }
                }
            }
        }
*/
/*        stage('Staging Deployment') {
            steps {
                script {
                    deploy()
                }
            }
        }
*/
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
