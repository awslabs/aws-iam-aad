Turn-key serverless solution using CloudFormation and ECS Fargate:


ATTENTION: In current setup-env-template.json, the value of container image is set to "111111111111.dkr.ecr.us-east-1.amazonaws.com/ss-docker-registry:latest". This is an image I have created in my own ECR for testing. Ideally we will replace this with an image that is available to all AWS customers. Until then, you should replace this image with another one in your own registry. To do this, create a docker image using the Dockerfile and other files in "docker" directory. Use this command:

docker build /path/to/directory/docker -t <tag name here (e.g. aad_aws_sso)>:latest

Once you create the Docker image locally, follow the instructions in AWS ECR console to push your image into your private ECR registry.

Your ECR registry must be in your primary AWS account (central account). After pushing the image into ECR, replace the container image string in setup-env-template.json to the one associated with your own ECR image.

Note: Currently AWS Fargate is only available in us-east-1 region. Therefore, you would have to deploy setup-env-template.json into that region. This should not be an important restriction, because AWS IAM is a global service. In future, as AWS Fargate becomes available in other regions, even this restriction will be eliminated.