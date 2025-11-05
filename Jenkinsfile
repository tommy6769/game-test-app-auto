pipeline
{
    agent any
    environment 
    {
        // Docker Hub credentials ID stored in Jenkins
        DOCKERHUB_CREDENTIALS ='CYBR-3120'
        IMAGE_NAME ='tommy6769/levigametest'
    }

    stages
    {
        stage('Cloning Git')
        {
            steps
            {
                checkout scm
            }
        }

        stage('SAST')
        {
            steps
            {
                sh 'echo Running SAST scan with snyk...'
            }
        }

        stage('BUILD-AND-TAG')
        {
            agent {label 'CYBER-3120'}
            
            steps
            {


                script
                {
                    // Build docker image using jenkins docker pipeline API
                    echo "Building Docker image ${IMAGE_NAME}..."
                    app = docker.build("${IMAGE_NAME}")
                    app.tag("latest")

                }
            }
        }

        stage('POST-TO-DOCKERHUB')
        {
            agent {label 'CYBER-3120'}
            
            steps
            {


                script
                {
                    echo "Pushing image ${IMAGE_NAME}:latest to Docker Hub..."
                    docker.withRegistry('https://registry.hub.docker.com',"${DOCKERHUB_CREDENTIALS}")
                    {
                     app.push("latest")
                    }

                }
            }
        }

        stage('DAST')
        {
            steps
            {
                sh 'echo Running DAST scan...'
            }
        }        

        stage('Deployment')
        {
            agent {label 'CYBER-3120'}
            
            steps
            {
                echo 'Starting deployment using docker-compose...'
                script
                {
                    dir("${WORKSPACE}")
                    sh '''
                        docker-compose down
                        docker-compose up -d
                        docker ps
                    '''

                }
                    echo 'Deployment completed successfully!'
            }
        }        
    }        
}
