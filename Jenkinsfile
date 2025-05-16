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
        DEPLOY_DIR = '/home/${INSTANCE_USER}/2FASecureGuard'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Init') {
            steps {
                script {
                    // We're always working on main branch directly
                    echo "Working on main branch, direct push workflow"
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
                    pip freeze > requirements.lock
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
                    rm -rf dist/  # Clean previous artifacts to avoid cached wheel files
                    python -m build
                """
            }
        }

        stage('Deploy') {
            // Always deploy since we're working directly on main without PRs
            when {
                expression { return true }  // Always run the deploy stage
            }
            steps {
                echo "Deploying source code and built package to server ..."

                // Ensure SSH keys are properly set up
                sshagent(['instance-ssh-credentials']) {  // Replace with your SSH credentials ID
                    sh """
                        # Create deploy directory if it doesn't exist
                        ssh ${INSTANCE_USER}@${INSTANCE_HOST} "mkdir -p ${DEPLOY_DIR}"

                        # Create a temporary tar of the source code (excluding unnecessary files)
                        tar --exclude="venv" --exclude=".git" --exclude="__pycache__" --exclude="*.pyc" -czf deploy-source.tar.gz .

                        # Copy the source code and package files to the server
                        scp deploy-source.tar.gz dist/2fasecureguard-*.whl requirements.lock ${INSTANCE_USER}@${INSTANCE_HOST}:${DEPLOY_DIR}/

                        # Extract the source code on the server
                        ssh ${INSTANCE_USER}@${INSTANCE_HOST} "cd ${DEPLOY_DIR} && tar -xzf deploy-source.tar.gz && rm deploy-source.tar.gz"

                        # Install and restart on the server
                        ssh ${INSTANCE_USER}@${INSTANCE_HOST} "
                            # Activate virtualenv on remote server (create if it doesn't exist)
                            if [ ! -d ${DEPLOY_DIR}/venv ]; then
                                python3 -m venv ${DEPLOY_DIR}/venv
                            fi
                            . ${DEPLOY_DIR}/venv/bin/activate

                            # Install the uploaded package
                            pip install --upgrade pip
                            pip install -r ${DEPLOY_DIR}/requirements.lock
                            pip install --force-reinstall ${DEPLOY_DIR}/*.whl

                            # Restart the application (if configured as a systemd service)
                            if systemctl is-active --quiet 2fasecureguard.service; then
                                sudo systemctl restart 2fasecureguard.service
                                sudo systemctl status 2fasecureguard.service --no-pager
                            else
                                echo 'Service not running or not configured'
                                exit 1  # Fail the pipeline if service is not running
                            fi
                        "
                    """
                }
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
            echo 'Build succeeded!'
        }

        failure {
            echo 'Build failed!'
        }
    }
}