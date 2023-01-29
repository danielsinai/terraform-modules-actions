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
    

def report_action_to_port(version, example, inputs, token):
    """
            Reports to Port on a new action based on provided inputs.
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
    
    action_json = {
        "identifier": f"{example}__{MODULE_NAME}__{version.replace('.', '_')}".replace('/', '_'),
        "title": f"Create {example}-{version}".replace('_', ' ').title(),
        "trigger": "CREATE",
        "userInputs": inputs,
        "description": f"More details about this version can be found here https://registry.terraform.io/modules/{MODULE_NAME}/{version}/examples/{example}",
        "invocationMethod": {
            "type": "GITHUB",
            "org": "danielsinai", 
            "repo": "terraform-modules-actions", 
            "workflow": "execute-module.yml",
            "omitUserInputs": True    
        }
    }

    response = requests.post(f'{API_URL}/blueprints/{BLUEPRINT_IDENTIFIER}/actions',
                             json=action_json, headers=headers)
    
    if response.status_code == 409:
        response = requests.put(f'{API_URL}/blueprints/{BLUEPRINT_IDENTIFIER}/actions/{action_json["identifier"]}',
                                json=action_json, headers=headers)
    
    return response.status_code

def report_destroy_action_to_port(token):
    """
            Reports to Port on a new action based on provided inputs.
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
    
    action_json = {
        "identifier": f"destroy",
        "title": f"Destroy all resources",
        "trigger": "DELETE",
        "userInputs": {"properties": {}},
        "invocationMethod": {
            "type": "GITHUB",
            "org": "danielsinai", 
            "repo": "terraform-modules-actions", 
            "workflow": "destroy-module.yml"
        }
    }

    response = requests.post(f'{API_URL}/blueprints/{BLUEPRINT_IDENTIFIER}/actions',
                             json=action_json, headers=headers)
    
    if response.status_code == 409:
        response = requests.put(f'{API_URL}/blueprints/{BLUEPRINT_IDENTIFIER}/actions/{action_json["identifier"]}',
                                json=action_json, headers=headers)
    
    return response.status_code

def report_blueprint_to_port(schema, token):
    """
            Reports to Port on a new blueprint based on provided properties.
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

    schema.properties.update({"creator": {"type": "string", "title": "Creator", "format": "user"}})
    
    blueprint_json = {
        "identifier": f"{BLUEPRINT_IDENTIFIER}",
        "title": f"{BLUEPRINT_IDENTIFIER}".replace('-', ' ').title(),
        "icon": "GoogleCloud",
        "schema": schema
    }

    response = requests.post(f'{API_URL}/blueprints',
                             json=blueprint_json, headers=headers)
    
    if response.status_code == 409:
        response = requests.put(f'{API_URL}/blueprints/{BLUEPRINT_IDENTIFIER}',
                                json=blueprint_json, headers=headers)
    
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

    if input['default'] == '' or input['default'] == None or input['default'] == 'null':
        if input['required']:
            input_final_json_required.append(input['name'])

        input_final_json_properties[input['name']] = {
            "type": type,
            "description": input['description'],
            "title": input['name'].replace('_', ' ').title(),
        }

def build_output(output, output_final_json_properties):
    type = 'string'
    format = None

    if 'url' in output['name']:
        format = 'url'

    if format != None:
        output_final_json_properties[output['name']] = {
            "type": type,
            "description": output['description'],
            "title": output['name'].replace('_', ' ').title(),
            "format": format
        }
    else:
        output_final_json_properties[output['name']] = {
            "type": type,
            "description": output['description'],
            "title": output['name'].replace('_', ' ').title(),
        }

def main():
    port_token = get_port_api_token()

    """
     Reporting common outputs as Port blueprint
    """
    properties_json_per_version = {}

    for version in MODULE_VERSIONS.split(','):
        properties_json = {}
        terraform_module = get_terraform_module(version)
        for output in terraform_module['root']['outputs']:

            for example in terraform_module['examples']:
                if example['name'] not in MODULE_EXAMPLES.split(','):
                    continue

                for example_output in example['outputs']:
                    if example_output['name'] == output['name']:
                        build_output(example_output, properties_json)

        properties_json_per_version[version] = properties_json
    
    final_properties = {}

    for version in MODULE_VERSIONS.split(','):
        for property in properties_json_per_version[version]:
            if property not in final_properties:
                final_properties[property] = properties_json_per_version[version][property]

    report_blueprint_to_port({ "properties": final_properties, "required": [] }, port_token)

    """
     Reporting examples as CREATE Port actions
    """
    for version in MODULE_VERSIONS.split(','):
        terraform_module = get_terraform_module(version)
        for example in terraform_module['examples']:
            if example['name'] not in MODULE_EXAMPLES.split(','):
                continue
            
            input_final_json_properties = {}
            input_final_json_required = []

            for input in example['inputs']:
                build_input(input, input_final_json_properties, input_final_json_required)
            
            report_action_to_port(version, example['name'], { "properties": input_final_json_properties, "required": list(set(input_final_json_required)) }, port_token)
    report_destroy_action_to_port(port_token)
if __name__ == '__main__':
    main()
