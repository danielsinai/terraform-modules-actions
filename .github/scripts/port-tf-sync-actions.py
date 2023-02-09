#!/bin/python

import json
import os
import requests
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CLIENT_ID = os.environ.get("PORT_CLIENT_ID")
CLIENT_SECRET = os.environ.get("PORT_CLIENT_SECRET")
API_URL = os.environ.get("API_URL")
TF_CLOUD_TOKEN = os.environ.get("TF_CLOUD_TOKEN")
MODULES_TO_EXPORT = os.environ.get("MODULES_TO_EXPORT")
DEPLOYMENT_BLUEPRINT_IDENTIFIER = "Deployment"
MODULE_VERSION_BLUEPRINT_IDENTIFIER = "Module-Catalog"

MODULES_TO_EXPORT_JSON = json.loads(MODULES_TO_EXPORT)

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

def get_terraform_module(module, version):
    """
    Returns:
    Get a Terraform module from Terraform Cloud
    This function uses TF_CLOUD_TOKEN from config
    """

    headers = {'Authorization' : f'Bearer {TF_CLOUD_TOKEN}'}

    module_response = requests.get(
        f"https://app.terraform.io/api/registry/public/v1/modules/{module}/{version}", headers=headers)
    
    return module_response.json()
    

def report_action_to_port(module, version, example, inputs, token):
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
        "identifier": f"{example}__{module}__{version.replace('.', '_')}".replace('/', '_'),
        "title": f"Create {example}-{version}".replace('_', ' ').title(),
        "trigger": "CREATE",
        "userInputs": inputs,
        "description": f"More details about this version can be found here https://registry.terraform.io/modules/{module}/{version}/examples/{example}",
        "invocationMethod": {
            "type": "GITHUB",
            "org": "danielsinai", 
            "repo": "terraform-modules-actions", 
            "workflow": "execute-module.yml",
            "omitUserInputs": True    
        }
    }

    response = requests.post(f'{API_URL}/blueprints/{DEPLOYMENT_BLUEPRINT_IDENTIFIER}/actions', json=action_json, headers=headers)
    
    if response.status_code == 409:
        response = requests.put(f'{API_URL}/blueprints/{DEPLOYMENT_BLUEPRINT_IDENTIFIER}/actions/{action_json["identifier"]}',json=action_json, headers=headers)
    
    response = requests.post(f'{API_URL}/blueprints/{MODULE_VERSION_BLUEPRINT_IDENTIFIER}/entities?upsert=true',
                              json={
                                "identifier": action_json["identifier"],
                                "title": action_json["title"],
                                "properties": {
                                    "module": module, "version": version, "example": example
                                }
                                }, headers=headers)

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

    response = requests.post(f'{API_URL}/blueprints/{DEPLOYMENT_BLUEPRINT_IDENTIFIER}/actions',
                             json=action_json, headers=headers)
    
    if response.status_code == 409:
        response = requests.put(f'{API_URL}/blueprints/{DEPLOYMENT_BLUEPRINT_IDENTIFIER}/actions/{action_json["identifier"]}',
                                json=action_json, headers=headers)
    
    return response.status_code

def report_blueprints_to_port(token):
    """
            Reports to Port on a new blueprint based on provided properties.
            Args:
                    inputs: Json of the terraform inputs
                    token: PortAPI Token
            Return:
                    Status code of POST command sent to Port
    """
    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    module_version_blueprint_json = {
        "identifier": f"{MODULE_VERSION_BLUEPRINT_IDENTIFIER}",
        "title": f"{MODULE_VERSION_BLUEPRINT_IDENTIFIER}".replace('-', ' ').title(),
        "icon": "Terraform",
        "schema": {
            "properties": {
                "version": {
                    "type": "string", "title": "Version"
                },
                "module": {
                    "type": "string", "title": "Module"
                },
                "example": {
                    "type": "string", "title": "Example"
                },
            },
            "required": []
        },
        "calculationProperties": {
            "deploy": {
                "type": "string",
                "format": "url",
                "title": "Deploy",
                "calculation": "https://app.getport.io/self-serve?action= + '.identifier'"
            }
        }
    }

    response = requests.post(f"{API_URL}/blueprints", json=module_version_blueprint_json, headers=headers)
    
    if response.status_code == 409:
        response = requests.put(f"{API_URL}/blueprints/{MODULE_VERSION_BLUEPRINT_IDENTIFIER}", json=module_version_blueprint_json, headers=headers)

    deployment_blueprint_json = {
        "identifier": f"{DEPLOYMENT_BLUEPRINT_IDENTIFIER}",
        "title": f"{DEPLOYMENT_BLUEPRINT_IDENTIFIER}".replace('-', ' ').title(),
        "icon": "Deployment",
        "schema": {
            "properties": {
                "creator": {
                    "type": "string", "title": "Creator", "format": "user"
                },
                "configuration": {
                    "type": "object", "title": "Configuration"
                }, 
                "ttl": {
                    "type": "string", "title": "TTL", "format": "timer"
                }
            },
            "required": []
        },
        "relations": {
            "module": {
                "target": f"{MODULE_VERSION_BLUEPRINT_IDENTIFIER}",
                "title": "Module",
                "required": True
            }
        }
    }

    response = requests.post(f'{API_URL}/blueprints',json=deployment_blueprint_json, headers=headers)

    if response.status_code == 409:
        response = requests.put(f'{API_URL}/blueprints/{DEPLOYMENT_BLUEPRINT_IDENTIFIER}',json=deployment_blueprint_json, headers=headers)

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

    report_blueprints_to_port(port_token)
    for module_to_export in MODULES_TO_EXPORT_JSON:
        for version in module_to_export["versions"]:
            terraform_module = get_terraform_module(module_to_export['module'], version)
            for example in terraform_module['examples']:
                if example['name'] not in module_to_export["examples"]:
                    continue
                
                input_final_json_properties = {}
                input_final_json_required = []

                for input in example['inputs']:
                    build_input(input, input_final_json_properties, input_final_json_required)
                
                report_action_to_port(module_to_export['module'], version, example['name'], { "properties": input_final_json_properties, "required": list(set(input_final_json_required)) }, port_token)
    report_destroy_action_to_port(port_token)
if __name__ == '__main__':
    main()
