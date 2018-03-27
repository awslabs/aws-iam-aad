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

#!/bin/bash

#Script directory. Other files are expected to be in this directory. (i.e. public key pem file, SAML certificate XML, App Manigest JSON and the cross-account AWS roles list json files)

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Please enter IP address of EC2 instance. You should have created this EC2 instance through the CloudFormation template setup-env-cfn-template.json. You can get the IP address from that CloudFormation Stack's Output tab."
read IP

#Acquiring pem key file
PEM=""
for f in "${DIR}"/*
do
	if [[ "${f}" = *.pem ]]
	then
		PEM="${f}"
		break;
	fi
done

if [[ "${PEM}" = "" ]]
then
	echo "Could not find pem file in script directory. Please specify path for pem file. This is required to copy all files into the destination EC2 instance."
	read PEM
fi

#Transmitting setup files
for f in "${DIR}"/*
do
	if [[ "${f}" != "*.pem" ]]
	then
		echo "scp -i ${PEM} ${f} \"ec2-user@${IP}:/home/ec2-user/scripts/setup\"";scp -i "${PEM}" "${f}" "ec2-user@${IP}:/home/ec2-user/scripts/setup"
	fi
done

#Transmitting docker files
for f in "${DIR}/../docker"/*
do
	echo "scp -i ${PEM} ${f} \"ec2-user@${IP}:/home/ec2-user/scripts/docker\"";scp -i "${PEM}" "${f}" "ec2-user@${IP}:/home/ec2-user/scripts/docker"
done

#Connecting to instance which automatically runs setup.ps1 script
ssh -i "${PEM}" "ec2-user@${IP}"


