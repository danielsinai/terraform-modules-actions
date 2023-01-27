#!/bin/python

import json
import os
import logging
import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TF_CLOUD_TOKEN = os.environ.get("TF_CLOUD_TOKEN")
TF_CLOUD_TEAM_TOKEN = os.environ.get("TF_CLOUD_TEAM_TOKEN")
ORGANIATION_NAME = os.environ.get("ORGANIATION_NAME")
PORT_PAYLOAD = os.environ.get("PORT_PAYLOAD")

ACTION_IDENTIFIER = json.loads(PORT_PAYLOAD)['payload']['action']['identifier']
RUN_ID = json.loads(PORT_PAYLOAD)['context']['runId']
VARIABLES = json.loads(PORT_PAYLOAD)['payload']['properties']
BLUEPRINT_IDENTIFIER = json.loads(PORT_PAYLOAD)['context']['blueprint']

def create_hcl_file_to_upload(variables):
    """
    Returns:
    Create a HCL file to upload to Terraform Cloud
    """
    os.mkdir("to_upload")

    action_splited = ACTION_IDENTIFIER.split("__")
    example = action_splited[0]
    module_name = action_splited[1].replace("_", "/")
    version = action_splited[2].replace("_", ".")

    hcl_file = open("to_upload/main.tf", "w")
    # intialization of required providers
    hcl_file.write("terraform {\n")
    hcl_file.write("\trequired_providers {\n")
    hcl_file.write("\t\tgoogle = {\n")
    hcl_file.write(f"\t\t\tsource = \"hashicorp/google\"\n")
    hcl_file.write(f"\t\t\tversion = \"4.50.0\"\n")
    hcl_file.write("\t\t}\n")
    hcl_file.write("\tgoogle-beta = {\n")
    hcl_file.write(f"\t\t\tsource = \"hashicorp/google-beta\"\n")
    hcl_file.write(f"\t\t\tversion = \"4.50.0\"\n")
    hcl_file.write("\t\t}\n")
    hcl_file.write("\t\tport-labs = {\n")
    hcl_file.write(f"\t\t\tsource = \"port-labs/port-labs\"\n")
    hcl_file.write(f"\t\t\tversion = \"0.6.0\"\n")
    hcl_file.write("\t\t}\n")
    hcl_file.write("\t}\n")    
    hcl_file.write("}\n")

    # providers configuration
    hcl_file.write("provider \"google\" {\n")
    hcl_file.write("\tcredentials = base64decode(var.GCP_CREDS)\n")
    hcl_file.write("}\n")
    hcl_file.write("provider \"google-beta\" {\n")
    hcl_file.write("\tcredentials = base64decode(var.GCP_CREDS)\n")
    hcl_file.write("}\n")
    hcl_file.write("provider \"port-labs\" {\n")
    hcl_file.write("\tclient_id = var.PORT_CLIENT_ID\n")
    hcl_file.write("\tsecret = var.PORT_CLIENT_SECRET\n")
    hcl_file.write("}\n")

    # variables
    hcl_file.write("variable \"GCP_CREDS\" {\n")
    hcl_file.write("\ttype = string\n")
    hcl_file.write("}\n")
    hcl_file.write("variable \"PORT_CLIENT_ID\" {\n")
    hcl_file.write("\ttype = string\n")
    hcl_file.write("}\n")
    hcl_file.write("variable \"PORT_CLIENT_SECRET\" {\n")
    hcl_file.write("\ttype = string\n")
    hcl_file.write("}\n")
    # data
    hcl_file.write(f"module \"{RUN_ID}\""+ " {\n")
    hcl_file.write(f"\tsource = \"{module_name}//examples/{example}\"\n")
    hcl_file.write(f"\tversion = \"{version}\"\n")
    
    for variable in variables:
        hcl_file.write(f"\t{variable['name']} = \"{variable['value']}\"\n")

    hcl_file.write("}\n")

    hcl_file.write(f"resource \"port-labs_entity\" \"{RUN_ID}\"" + " {\n")
    hcl_file.write(f"\ttitle = \"module.{RUN_ID}.service_name\"\n")
    hcl_file.write(f"\tblueprint = \"{BLUEPRINT_IDENTIFIER}\"\n")
    for output in ['service_url', 'service_name']:
        hcl_file.write("\tproperties {\n")
        hcl_file.write(f"\t\tname = \"{output}\"\n")
        hcl_file.write(f"\t\tvalue = module.{RUN_ID}.{output}\n")
        hcl_file.write("\t}\n")

    hcl_file.write("}\n")
    hcl_file.close()

    os.popen(f"tar -zcvf \"content.tar.gz\" -C \"to_upload\" ." )

    return "content.tar.gz"
    
def create_terraform_workspace(run_id, hcl_zip):
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
                "auto-apply": False,
            }
        }
    }

    workspace_response = requests.post(
        f"https://app.terraform.io/api/v2/organizations/{ORGANIATION_NAME}/workspaces", headers=headers, json=workspace_payload)
    
    configuration_version_response = requests.post(
        f"https://app.terraform.io/api/v2/workspaces/{workspace_response.json()['data']['id']}/configuration-versions", headers=user_headers, json={
            "data": {
                "type": "configuration-versions",
        }})
    
    if configuration_version_response.status_code > 299: 
        raise Exception(f"Error creating configuration version for workspace {run_id} with status code {configuration_version_response.status_code} and response {configuration_version_response.json()}")

    os.popen(
        f"curl \
            --header \"Content-Type: application/octet-stream\" \
            --request PUT \
            --data-binary @\"{hcl_zip}\" \
            {configuration_version_response.json()['data']['attributes']['upload-url']}"
    )    
    

def main():
    variables_list = [{"name": key, "value": value} for key, value in VARIABLES.items()]
    
    hcl_zip = create_hcl_file_to_upload(variables_list)
    create_terraform_workspace(RUN_ID, hcl_zip)

if __name__ == '__main__':
    main()
