#Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  
#  Licensed under the Apache License, Version 2.0 (the "License").
#  You may not use this file except in compliance with the License.
#  A copy of the License is located at
#  
#      http://www.apache.org/licenses/LICENSE-2.0
#  
#  or in the "license" file accompanying this file. This file is distributed 
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either 
#  express or implied. See the License for the specific language governing 
#  permissions and limitations under the License.#>

FROM amazonlinux
SHELL ["/bin/sh", "-c"]
RUN curl https://packages.microsoft.com/config/rhel/7/prod.repo | tee /etc/yum.repos.d/microsoft.repo; \
    yum install -y powershell; \
	mkdir /docker
COPY . /docker
RUN pwsh -Command /docker/install.ps1
ENTRYPOINT ["pwsh"] #, "-command", "/docker/run-ps-script.ps1"]
SHELL ["/opt/microsoft/powershell/6.0.0/pwsh", "-Command"]
ENV AppBucketName="aadawssso" \
    Region="us-east-1" \
	AppName="aad_aws_sso" \
	KmsKeyId="alias/aws/ssm" \
	NamingConvention="AWS {0} - {1}" \
	SaveTranscriptToS3="true"
CMD ["/docker/run.ps1"]