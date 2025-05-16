pipeline {
    agent any

    environment {
        // Get the Python path from the environment
        PYTHON_PATH = sh(script: 'which python3', returnStdout: true).trim()

        // Define path to the virtual environment inside the workspace
        VENV = "${WORKSPACE}/venv"

        // Get sensitive instance details from Jenkins credentials
        INSTANCE_HOST = credentials('INSTANCE_HOST')
        INSTANCE_USER = credentials('INSTANCE_USER')

        // Directory on the EC2 server where the app will be deployed
        DEPLOY_DIR = '/home/ec2-user/2FASecureGuard'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Init') {

            // Determine if the build is for a Pull Request (PR)
            steps {
                script {
                    IS_PR = env.CHANGE_ID ? true : false
                }
            }
        }

        stage('Setup') {
            steps {
                echo 'Setting up Python virtual environment and installing dependencies...'

                // Create virtual environment, activate it, and install dependencies
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
                echo 'Running flake8 linter to check code quality...'

                // Activate virtualenv, install flake8, and run linting
                sh """
                    . ${VENV}/bin/activate
                    pip install flake8
                    flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics '--exclude=venv/,.*,__pycache__,docs/'
                """
            }
        }

        stage('Test') {
            steps {
                echo 'Running tests with pytest and generating coverage report...'
                sh """
                    . ${VENV}/bin/activate
                    pip install pytest pytest-cov
                    mkdir -p test-reports
                    pytest --junitxml=test-reports/results.xml --cov=. --cov-report=xml:coverage.xml
                """
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'test-reports/results.xml'
                    publishCoverage adapters: [coberturaAdapter(path: 'coverage.xml')]
                    script {
                        if (env.CHANGE_ID) {
                            def comment = "Test Results: ${currentBuild.currentResult}"
                            pullRequest.comment(comment)
                        }
                    }
                }
            }
        }

        stage('Build') {
            steps {
                echo 'Building Python package from source...'

                // Activate virtualenv, install build tool, and create distributable package
                sh """
                    . ${VENV}/bin/activate
                    pip install build
                    python -m build
                """
            }
        }

        stage('Deploy') {
            // Only deploy on PRs or on main branch
            when {
                anyOf {
                    branch 'main'
                    expression { return env.CHANGE_ID != null }
                }
            }
            steps {
                echo "Deploying built package to server at ${INSTANCE_HOST}..."

                // Use Jenkins SSH Publisher plugin to transfer files and run commands remotely
                sshPublisher(
                    publishers: [
                        sshPublisherDesc(
                            configName: 'instance-ssh', // Defined in Jenkins global config
                            transfers: [
                                sshTransfer(
                                    sourceFiles: 'dist/*', // The built .whl or .tar.gz packages
                                    remoteDirectory: "${DEPLOY_DIR}", // Target directory on EC2
                                    execCommand: """
                                        # Activate virtualenv on remote server
                                        . ${DEPLOY_DIR}/venv/bin/activate

                                        # Install the uploaded package
                                        pip install ${DEPLOY_DIR}/*.whl

                                        # Restart the application (if configured as a systemd service)
                                        sudo systemctl restart myapp.service || echo "Service restart failed or not configured"
                                    """
                                )
                            ]
                        )
                    ]
                )
            }
        }
    }

    post {
        always {
            script {
                // Make sure cleanWs() is inside node context
                node {
                    cleanWs()
                }
            }
        }

        success {
            // Notify on success, especially if it’s a PR
            echo 'Build succeeded!'
            script {
                if (env.CHANGE_ID) {
                    pullRequest.comment("✅ All checks passed! Ready for review and merge.")
                }
            }
        }

        failure {
            // Notify on failure for visibility in the PR
            echo 'Build failed!'
            script {
                if (env.CHANGE_ID) {
                    pullRequest.comment("❌ Build failed. Please check the logs and fix the issues.")
                }
            }
        }
    }
}
