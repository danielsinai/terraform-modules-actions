#!/bin/python

import json
import os
import logging
import requests
import tarfile

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TF_CLOUD_TOKEN = os.environ.get("TF_CLOUD_TOKEN")
TF_CLOUD_TEAM_TOKEN = os.environ.get("TF_CLOUD_TEAM_TOKEN")
ORGANIATION_NAME = os.environ.get("ORGANIATION_NAME")
PORT_PAYLOAD = os.environ.get("PORT_PAYLOAD")

ACTION_IDENTIFIER = json.loads(PORT_PAYLOAD)['payload']['action']['identifier']
RUN_ID = json.loads(PORT_PAYLOAD)['context']['runId']
VARIABLES = json.loads(PORT_PAYLOAD)['payload']['properties']


def create_hcl_file_to_upload(variables):
    """
    Returns:
    Create a HCL file to upload to Terraform Cloud
    """
    os.mkdir("to_upload")

    action_splited = ACTION_IDENTIFIER.split("--")
    example = action_splited[0]
    module_name = action_splited[1]
    version = action_splited[2].replace("_", ".")

    hcl_file = open("to_upload/main.tf", "w")
    hcl_file.write(f"module \"{RUN_ID}\""+ " {\n")
    hcl_file.write(f"\tsource = \"{module_name}//examples/{example}\"\n")
    hcl_file.write(f"\tversion = \"{version}\"\n")

    #for variable in variables:
    #    hcl_file.write(f"\t{variable['name']} = \"{variable['value']}\"\n")

    hcl_file.write("}\n")
    hcl_file.close()

    tar = tarfile.open("to_upload.tar.gz", "w:gz")
    tar.add('to_upload/main.tf')
    tar.close()

    return "to_upload.tar.gz"
    
def create_terraform_workspace(run_id, terraform_inputs, hcl_zip):
    """
    Returns:
    Create a Terraform workspace in Terraform Cloud
    This function uses TF_CLOUD_TOKEN from config
    """

    headers = {'Authorization' : f'Bearer {TF_CLOUD_TOKEN}', 'Content-Type': 'application/vnd.api+json'}
    user_headers = {'Authorization' : f'Bearer {TF_CLOUD_TEAM_TOKEN}', 'Content-Type': 'application/vnd.api+json'}

    workspace_payload = {
        "data": {
            "type": "workspaces",
            "attributes": {
                "name": run_id,
                "auto-apply": True,
            }
        }
    }

    workspace_response = requests.post(
        f"https://app.terraform.io/api/v2/organizations/{ORGANIATION_NAME}/workspaces", headers=headers, json=workspace_payload)
    
    if workspace_response.status_code < 299:
        for input in terraform_inputs:
            attributes = {
                "key": input['name'],
                "value": input['value'],
                "decsription": "",
                "sensitive": False,
                "hcl": False,
                "category": "terraform"
            }

            variables_data = {
                "data": {
                    "type": "vars",
                    "attributes": attributes
                }
            }

            variables_response = requests.post(
                f"https://app.terraform.io/api/v2/workspaces/{workspace_response.json()['data']['id']}/vars", headers=user_headers, json=variables_data)
            
            if variables_response.status_code > 299:
                raise Exception(f"Error creating variables for workspace {run_id} with status code {variables_response.status_code} and response {variables_response.json()}")                
    

    configuration_version_response = requests.post(
        f"https://app.terraform.io/api/v2/workspaces/{workspace_response.json()['data']['id']}/configuration-versions", headers=user_headers, json={
            "data": {
                "type": "configuration-versions",
        }})
    
    if configuration_version_response.status_code > 299: 
        raise Exception(f"Error creating configuration version for workspace {run_id} with status code {configuration_version_response.status_code} and response {configuration_version_response.json()}")

    files = {'file': open(hcl_zip, 'rb')}

    upload_response = requests.put(
        configuration_version_response.json()['data']['attributes']['upload-url'], headers=headers,files=files
    )    

    if upload_response.status_code > 299:
        raise Exception(f"Error uploading configuration version for workspace {run_id} with status code {upload_response.status_code} and response {upload_response.json()}")
    
    return workspace_response.json()        
    
    

def main():
    variables_list = [{"name": key, "value": value} for key, value in VARIABLES.items()]
    
    hcl_zip = create_hcl_file_to_upload(variables_list)
    #create_terraform_workspace(RUN_ID, variables_list, hcl_zip)

if __name__ == '__main__':
    main()