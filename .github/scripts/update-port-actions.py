#!/bin/python

import os
import requests
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CLIENT_ID = os.environ.get("PORT_CLIENT_ID")
CLIENT_SECRET = os.environ.get("PORT_CLIENT_SECRET")
API_URL = os.environ.get("API_URL")
TF_CLOUD_TOKEN = os.environ.get("TF_CLOUD_TOKEN")
MODULE_NAME = os.environ.get("MODULE_NAME")
MODULE_VERSIONS = os.environ.get("MODULE_VERSIONS")
MODULE_EXAMPLES = os.environ.get("MODULE_EXAMPLES")
BLUEPRINT_IDENTIFIER = os.environ.get("BLUEPRINT_IDENTIFIER")

def get_port_api_token():
    """
    Returns:
    Get a Port API access token
    This function uses CLIENT_ID and CLIENT_SECRET from config
    """

    credentials = {'clientId': CLIENT_ID, 'clientSecret': CLIENT_SECRET}

    token_response = requests.post(
        f"{API_URL}/auth/access_token", json=credentials)

    return token_response.json()['accessToken']

def get_terraform_module(version):
    """
    Returns:
    Get a Terraform module from Terraform Cloud
    This function uses TF_CLOUD_TOKEN from config
    """

    headers = {'Authorization' : f'Bearer {TF_CLOUD_TOKEN}'}

    module_response = requests.get(
        f"https://app.terraform.io/api/registry/public/v1/modules/{MODULE_NAME}/{version}", headers=headers)
    
    return module_response.json()
    

def report_to_port(version, example, inputs, token):
    """
            Reports to Port on a new action based on provided inputs.
            Uses threading to parallel-create the package entities in  Port.
            Args:
                    inputs: Json of the terraform inputs
                    token: PortAPI Token
            Return:
                    Status code of POST command sent to Port
    """
    logger.info('Fetching token')

    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    params = {
        'upsert': 'true'
    }

    action_json = {
        "identifier": f"{example}-{MODULE_NAME}-{version.replace('.', '_')}".replace('-', '_').replace('/', '_'),
        "title": f"Create {example}-{version}".replace('_', ' ').title(),
        "trigger": "CREATE",
        "userInputs": inputs,
        "description": f"More details about this version can be found (here)[https://registry.terraform.io/modules/{MODULE_NAME}/{version}/examples/{example}]",
        "invocationMethod": { "type": "MOCK" }
    }

    response = requests.post(f'{API_URL}/blueprints/{BLUEPRINT_IDENTIFIER}/actions',
                             json=action_json, headers=headers, params=params)
    
    if response.status_code == 409:
        response = requests.put(f'{API_URL}/blueprints/{BLUEPRINT_IDENTIFIER}/actions/{action_json["identifier"]}',
                                json=action_json, headers=headers, params=params)
        
    return response.status_code

def build_input(input, input_final_json_properties, input_final_json_required):
    type = ''

    if input['type'] == 'string':
        type = 'string'
    elif input['type'] == 'number':
        type = 'number'
    elif input['type'] == 'bool':
        type = 'boolean'
    elif 'list' in input['type'] or 'set' in input['type']:
        type = 'array'
    elif 'object' in input['type'] or 'map' in input['type'] :
        type = 'object'

    if input['default'] != '':
        if input['required']:
            input_final_json_required.append(input['name'])

        input_final_json_properties[input['name']] = {
            "type": type,
            "description": input['description'],
            "title": input['name'].replace('_', ' ').title(),
        }

def main():
    port_token = get_port_api_token()

    for version in MODULE_VERSIONS.split(','):
        terraform_module = get_terraform_module(version)
        for example in terraform_module['examples']:
            if example['name'] not in MODULE_EXAMPLES.split(','):
                continue
            
            input_final_json_properties = {}
            input_final_json_required = []

            for input in example['inputs']:
                build_input(input, input_final_json_properties, input_final_json_required)

            report_to_port(version, example['name'], { "properties": input_final_json_properties, "required": input_final_json_required }, port_token)

if __name__ == '__main__':
    main()