pipeline {
    agent any
    
    environment {
        // Set Python Path
        PYTHON_PATH = sh(script: 'which python3', returnStdout: true).trim()
        // Virtual Environment
        VENV = "${WORKSPACE}/venv"
        // Determine if this is a PR
        IS_PR = env.CHANGE_ID ? true : false
    }
    
    stages {
        stage('Setup') {
            steps {
                echo 'Setting up virtual environment...'
                sh """
                    ${PYTHON_PATH} -m venv ${VENV}
                    . ${VENV}/bin/activate
                    pip install --upgrade pip
                    pip install -r requirements.txt
                """
            }
        }
        
        stage('Lint') {
            steps {
                echo 'Running linting...'
                sh """
                    . ${VENV}/bin/activate
                    pip install flake8
                    flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
                """
            }
        }
        
        stage('Test') {
            steps {
                echo 'Running tests...'
                sh """
                    . ${VENV}/bin/activate
                    pip install pytest pytest-cov
                    pytest --cov=./ --cov-report=xml
                """
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: '**/test-results/*.xml'
                    publishCoverage adapters: [cobertura('**/coverage.xml')]
                    
                    // Update PR status if this is a PR
                    script {
                        if (env.CHANGE_ID) {
                            // This is a PR build
                            def comment = "Test Results: ${currentBuild.currentResult}"
                            pullRequest.comment(comment)
                        }
                    }
                }
            }
        }
        
        stage('Build') {
            steps {
                echo 'Building package...'
                sh """
                    . ${VENV}/bin/activate
                    pip install build
                    python -m build
                """
            }
        }
        
        stage('Deploy to Staging') {
            when {
                expression { return env.CHANGE_ID != null } // Only for PRs
            }
            steps {
                echo 'Deploying to staging environment...'
                // Add your staging deployment steps here
                // This could deploy to a test environment for verification
                sh """
                    . ${VENV}/bin/activate
                    echo "Deploying to staging with PR #${env.CHANGE_ID}"
                    # Add your staging deployment commands here
                """
            }
        }
        
        stage('Deploy to Production') {
            when {
                allOf {
                    branch 'main'  // Only from main branch
                    not { expression { return env.CHANGE_ID != null } } // Not a PR
                }
            }
            steps {
                echo 'Deploying to production...'
                // Add your production deployment steps here
                sh """
                    . ${VENV}/bin/activate
                    echo "Deploying to production"
                    # Add your production deployment commands here
                """
            }
        }
    }
    
    post {
        always {
            echo 'Pipeline completed'
            // Clean up workspace
            cleanWs()
        }
        success {
            echo 'Build succeeded!'
            script {
                if (env.CHANGE_ID) {
                    pullRequest.comment("✅ All checks passed! Ready for review and merge.")
                }
            }
        }
        failure {
            echo 'Build failed!'
            script {
                if (env.CHANGE_ID) {
                    pullRequest.comment("❌ Build failed. Please check the logs and fix the issues.")
                }
            }
        }
    }
}