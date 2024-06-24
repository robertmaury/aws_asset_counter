
from botocore.errorfactory import ClientError
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

def aws_acm_certificate(session, regions):
    total_certificates = 0
    global_certificates_tracked = False

    for region in regions:
        acm_client = session.client('acm', region_name=region)
        paginator = acm_client.get_paginator('list_certificates')
        page_iterator = paginator.paginate()

        for page in page_iterator:
            for certificate in page['CertificateSummaryList']:
                cert_arn = certificate['CertificateArn']
                cert_details = acm_client.describe_certificate(CertificateArn=cert_arn)

                # Check if the certificate is not managed by AWS (including the root CAs)
                if 'CreatedBy' in cert_details['Certificate'] and cert_details['Certificate']['CreatedBy'] == 'Amazon':
                    continue 

                global_certificate = False
                
                if cert_details['Certificate']['Type'] == 'AMAZON_ISSUED':
                    continue
                
                # Checking if the certificate is a global resource and if it is already tracked
                if cert_details['Certificate'].get('DomainValidationOptions'):
                    for resource_record in cert_details['Certificate']['DomainValidationOptions']:
                        if resource_record.get('ResourceRecord'):
                            global_certificate = True
                            break

                if global_certificate and global_certificates_tracked:
                    continue

                if global_certificate:
                    global_certificates_tracked = True
                
                total_certificates += 1
    
    return total_certificates

def aws_ami(session, regions):
    

    ami_count = 0
    visited_ami_ids = set()  # To avoid global resources counted multiple times

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)

        paginator = ec2_client.get_paginator('describe_images')
        response_iterator = paginator.paginate(Owners=['self'])

        for response in response_iterator:
            for image in response['Images']:
                ami_id = image['ImageId']
                is_managed_by_aws = (image.get('CreationDate') is None or
                                     image['Name'].startswith('aws') or
                                     'amazon' in image['Name'].lower())

                if not is_managed_by_aws and ami_id not in visited_ami_ids:
                    ami_count += 1
                    visited_ami_ids.add(ami_id)

    return ami_count

def aws_api_gateway_api_key(session, regions):
    '''
    Function to count the total number of AWS API Gateway API Keys across all specified regions,
    excluding resources that are created and managed by AWS.

    :param session: Boto3 session object
    :param regions: List of AWS regions
    :return: Total count of user-managed AWS API Gateway API Keys
    '''
    total_api_key_count = 0
    managed_by_aws_prefixes = ['aws-', 'amzn-']

    for region in regions:
        api_gateway = session.client('apigateway', region_name=region)
        
        # Paginate through results to ensure we get all API keys
        paginator = api_gateway.get_paginator('get_api_keys')
        page_iterator = paginator.paginate(limit=1000)
        
        for page in page_iterator:
            for api_key in page['items']:
                # Exclude API keys managed by AWS
                if not any(api_key['name'].startswith(prefix) for prefix in managed_by_aws_prefixes):
                    total_api_key_count += 1
                    
    return total_api_key_count

def aws_api_gateway_authorizer(session, regions):
    # Initialize count to zero
    total_authorizer_count = 0
    authorizer_ids = set()

    for region in regions:
        # Create a client for the API Gateway service in the region
        api_gateway_client = session.client('apigateway', region_name=region)

        # List all RestAPIs
        apis = api_gateway_client.get_rest_apis()['items']

        for api in apis:
            # List all authorizers for the given API
            authorizers = api_gateway_client.get_authorizers(restApiId=api['id'])['items']
            
            for authorizer in authorizers:
                # Exclude resources that are created and managed by AWS by filtering out based on a pattern or specific IDs
                # Assuming that managed by AWS resources follow a recognizable pattern, e.g., their names or IDs contain "AWS"
                if 'AWS' not in authorizer['name']:
                    authorizer_ids.add(authorizer['id'])  # Add to set to ensure uniqueness across regions

    # Return the total count of unique authorizer IDs
    total_authorizer_count = len(authorizer_ids)
    return total_authorizer_count

def aws_api_gateway_base_path_mapping(session, regions):
    """
    Count the total number of AWS API Gateway base path mappings across all specified regions.

    :param session: An existing boto3 session.
    :param regions: A list of AWS regions as strings.
    :return: Total count of base path mappings excluding AWS-managed resources.
    """
    total_count = 0
    
    for region in regions:
        client = session.client('apigateway', region_name=region)
        
        # List all rest APIs in the region
        rest_apis = client.get_rest_apis()
        rest_api_ids = [item['id'] for item in rest_apis.get('items', [])]
        
        for api_id in rest_api_ids:
            # List all base path mappings for each API
            base_path_mappings = client.get_base_path_mappings(domainName=api_id)
            
            for mapping in base_path_mappings.get('items', []):
                # Filter out AWS-managed resources (assuming by checking 'Managed' attribute)
                if 'Managed' not in mapping or not mapping['Managed']:
                    total_count += 1
                
    return total_count

    # Initialize total count for aws_api_gateway_documentation_part
    total_documentation_parts = 0
    global_documentation_parts = set()
    
    # Initialize the Boto3 client for API Gateway
    api_gateway_client = session.client('apigateway')

    # Loop through each region and count the documentation parts
    for region in regions:
        api_gateway_client = session.client('apigateway', region_name=region)
        try:
            # Paginate through all documentation parts in the region
            paginator = api_gateway_client.get_paginator('get_documentation_parts')
            for page in paginator.paginate():
                for item in page['items']:
                    # Exclude AWS managed documentation parts
                    if not item['id'].startswith('aws:'):
                        # Add to set for global resources to ensure uniqueness
                        global_documentation_parts.add(item['id'])
        except Exception as e:
            print(f"An error occurred in region {region}: {e}")
    
    # The total count of unique documentation parts
    total_documentation_parts = len(global_documentation_parts)
    return total_documentation_parts

def aws_api_gateway_documentation_version(session, regions):
    total_count = 0
    seen_apis = set()

    for region in regions:
        try:
            client = session.client('apigateway', region_name=region)
            apis = client.get_rest_apis(limit=500)

            for api in apis.get('items', []):
                if api['id'] not in seen_apis:
                    seen_apis.add(api['id'])

                    doc_versions = client.get_documentation_versions(restApiId=api['id'])
                    for version in doc_versions.get('items', []):
                        # Assuming there is a 'managedBy' field to indicate AWS-managed resources
                        if 'managedBy' not in version:
                            total_count += 1
                        
        except ClientError as e:
            print(f"An error occurred in region {region}: {e}")

    return total_count

def aws_api_gateway_domain_name(session, regions):
    

    def is_aws_managed(domain_name):
        # Placeholder function to check if the domain is AWS managed
        # A more elaborate check can be implemented based on the domain name pattern or tags.
        return 'aws' in domain_name.lower()

    counted_domains = set()  # Use set to ensure uniqueness
    
    for region in regions:
        client = session.client('apigateway', region_name=region)
        try:
            response = client.get_domain_names()
            domain_names = response.get('items', [])
            for domain in domain_names:
                domain_name = domain['domainName']
                if not is_aws_managed(domain_name):
                    counted_domains.add(domain_name)
        except ClientError as e:
            print(f"An error occurred in region {region}: {e}")
            continue
    
    total_domains = len(counted_domains)
    return total_domains

def aws_api_gateway_integration(session, regions):
    def is_managed_by_aws(resource):
        """Return True if the resource is managed by AWS."""
        aws_managed_patterns = [
            'aws:',
            'arn:aws:'
        ]
        return any(pattern in resource for pattern in aws_managed_patterns)

    api_gateway_integrations_count = 0
    already_counted_globals = set()

    for region in regions:
        client = session.client('apigateway', region_name=region)

        # Count RestApi resources
        response = client.get_rest_apis()
        rest_apis = response.get('items', [])

        for rest_api in rest_apis:
            if not is_managed_by_aws(rest_api['id']):
                # Get integrations
                resources = client.get_resources(restApiId=rest_api['id'])
                items = resources.get('items', [])
                for item in items:
                    if 'resourceMethods' in item:
                        for method in item['resourceMethods']:
                            integration = client.get_integration(
                                restApiId=rest_api['id'], 
                                resourceId=item['id'],
                                httpMethod=method
                            )
                            if 'uri' in integration and not is_managed_by_aws(integration['uri']):
                                api_gateway_integrations_count += 1

        # Update already_counted_globals to avoid double counting global resources
        already_counted_globals.add(region)

    return api_gateway_integrations_count

def aws_api_gateway_integration_response(session, regions):
    
    

    def get_api_gateway_integration_responses(client):
        integration_response_count = 0
        try:
            # Get all API Gateways
            apis = client.get_rest_apis()
            for api in apis.get('items', []):
                resources = client.get_resources(restApiId=api['id'])
                for resource in resources.get('items', []):
                    if 'resourceMethods' in resource:
                        for method in resource['resourceMethods']:
                            try:
                                response = client.get_integration(
                                    restApiId=api['id'],
                                    resourceId=resource['id'],
                                    httpMethod=method
                                )
                                if response:
                                    integration_response_count += len(response.get('integrationResponses', {}))
                            except ClientError as error:
                                # Handle specific errors here, if necessary
                                if error.response['Error']['Code'] != 'NotFoundException':
                                    raise error
        except ClientError as e:
            print(f"An error occurred: {e}")
        return integration_response_count

    # Initiate the total count
    total_integration_responses = 0
    # For each region, create a client and get the count
    for region in regions:
        client = session.client('apigateway', region_name=region)
        total_integration_responses += get_api_gateway_integration_responses(client)
    
    return total_integration_responses

def aws_api_gateway_method(session, regions):
    """
    Given a Boto3 session and a list of AWS regions, this function counts the total number
    of API Gateway methods across all regions. It excludes resources that are created
    and managed by AWS.

    Args:
    session (boto3.session.Session): An existing Boto3 session.
    regions (list): List of AWS regions to search.

    Returns:
    int: The total count of API Gateway methods.
    """
    api_gateway_methods_count = 0
    visited_methods = set()

    for region in regions:
        client = session.client('apigateway', region_name=region)
        paginator = client.get_paginator('get_rest_apis')

        for page in paginator.paginate():
            for item in page['items']:
                if item['name'].startswith('aws:'):
                    # Skip resources managed by AWS
                    continue
                
                rest_api_id = item['id']
                resources = client.get_resources(restApiId=rest_api_id)
                
                for resource in resources['items']:
                    if 'resourceMethods' in resource:
                        for method in resource['resourceMethods']:
                            method_id = f"{rest_api_id}-{resource['id']}-{method}"
                            if method_id not in visited_methods:
                                visited_methods.add(method_id)
                                api_gateway_methods_count += 1

    return api_gateway_methods_count

def aws_api_gateway_method_response(session, regions):
    
    

    api_gateway_client = session.client('apigateway')
    
    def is_aws_managed(resource_arn):
        # A common pattern in AWS-managed resources is the presence of "aws" in the ARN.
        return 'aws' in resource_arn.lower()
    
    total_method_response_count = 0
    unique_global_resources = set()

    for region in regions:
        region_client = session.client('apigateway', region_name=region)
        
        try:
            # Fetch the list of Rest APIs in the region
            rest_apis_response = region_client.get_rest_apis()
            rest_apis = rest_apis_response.get('items', [])
            
            for api in rest_apis:
                # Exclude AWS managed API endpoints
                if is_aws_managed(api['id']):
                    continue

                # Fetch resources for the given API
                resources_response = region_client.get_resources(restApiId=api['id'])
                resources = resources_response.get('items', [])
                
                for resource in resources:
                    # Filter our AWS managed resources
                    if is_aws_managed(resource['id']):
                        continue

                    # Count method responses
                    for method in resource.get('resourceMethods', {}).keys():
                        method_response = region_client.get_method_response(
                            restApiId=api['id'],
                            resourceId=resource['id'],
                            httpMethod=method,
                            statusCode="200"  # You can specify other or multiple status codes if needed
                        )
                        if is_aws_managed(method_response['responseModels']):
                            continue

                        total_method_response_count += 1

        except ClientError as e:
            print(f"An error occurred in region {region}: {e}")

    return total_method_response_count

def aws_api_gateway_model(session, regions):
    

    def list_models(client):
        paginator = client.get_paginator('get_models')
        models = []
        for page in paginator.paginate():
            models.extend(page['items'])
        return models

    total_models = 0
    seen_models = set()

    for region in regions:
        client = session.client('apigateway', region_name=region)
        
        models = list_models(client)
        for model in models:
            if not model['name'].startswith('aws-managed') and model['id'] not in seen_models:
                seen_models.add(model['id'])
                total_models += 1

    return total_models

def aws_api_gateway_request_validator(session, regions):
    # Initialize a set to track unique global resources
    unique_global_resources = set()
    # Initialize a counter for request validators
    total_request_validators = 0
    
    for region in regions:
        # Create a client for API Gateway in the given region
        client = session.client('apigateway', region_name=region)
        
        # Paginate through list_request_validators
        paginator = client.get_paginator('get_request_validators')
        page_iterator = paginator.paginate()
        
        for page in page_iterator:
            for validator in page['items']:
                # Check if the validator is AWS managed
                if not validator.get('managedBy') == 'AWS':
                    # Add to the counter
                    total_request_validators += 1
                    # If it's a global resource, add to the set
                    if validator[' id'] in unique_global_resources:
                        continue
                    else:
                        unique_global_resources.add(validator['id'])
    
    return total_request_validators

def aws_api_gateway_resource(session, regions):
    total_count = 0
    managed_by_aws_prefixes = ['aws', 'cloudfront', 'service', 'lambda']
    
    for region in regions:
        apigateway = session.client('apigateway', region_name=region)
        
        # Get a list of all API Gateway REST APIs in the region
        rest_apis = apigateway.get_rest_apis(limit=500)
        
        for rest_api in rest_apis.get('items', []):
            # Get a list of all resources for each REST API
            resources = apigateway.get_resources(restApiId=rest_api['id'], limit=500)
            
            for resource in resources.get('items', []):
                # Check if the resource is managed by AWS
                if not any(resource['path'].startswith(prefix) for prefix in managed_by_aws_prefixes):
                    total_count += 1
    
    return total_count

def aws_api_gateway_rest_api(session, regions):
    total_count = 0
    global_rest_apis = set()

    for region in regions:
        client = session.client('apigateway', region_name=region)
        paginator = client.get_paginator('get_rest_apis')
        page_iterator = paginator.paginate()

        for page in page_iterator:
            for rest_api in page['items']:
                # AWS managed resources typically have an arn starting with 'arn:aws:apigateway'
                if not rest_api['id'].startswith('aws-managed-'):
                    rest_api_id = rest_api['id']
                    if rest_api_id not in global_rest_apis:
                        global_rest_apis.add(rest_api_id)
                        total_count += 1

    return total_count

def aws_api_gateway_stage(session, regions):
    client = session.client('apigateway')
    total_stages = set()
    
    for region in regions:
        regional_client = session.client('apigateway', region_name=region)
        response = regional_client.get_rest_apis()

        for api in response.get('items', []):
            rest_api_id = api.get('id')

            stages_response = regional_client.get_stages(restApiId=rest_api_id)
            stages = stages_response.get('item', [])

            for stage in stages:
                stage_arn = f"arn:aws:apigateway:{region}::/restapis/{rest_api_id}/stages/{stage['stageName']}"
                if not stage.get('managedByAWS', False):  # Exclude resources managed by AWS
                    total_stages.add(stage_arn)

    # Count unique stages only once (accounts for global resources across regions)
    return len(total_stages)

def aws_api_gateway_usage_plan(session, regions):
    # Initialize a set to keep track of global resource ARNs
    global_resources = set()
    usage_plan_count = 0

    for region in regions:
        # Create a client for the API Gateway in the specified region
        client = session.client('apigateway', region_name=region)
        
        # Paginate through the usage plans
        paginator = client.get_paginator('get_usage_plans')
        page_iterator = paginator.paginate()
        
        for page in page_iterator:
            for usage_plan in page['items']:
                # We assume that AWS managed resources might have a specific arn prefix or a tag/key.
                # Adjust the condition based on actual criteria used to filter out AWS managed resources.
                
                arn = usage_plan['id']
                
                # Check if the usage plan is managed by AWS
                if 'aws:' in arn:
                    continue
                
                if arn not in global_resources:
                    global_resources.add(arn)
                    usage_plan_count += 1

    return usage_plan_count

def aws_api_gateway_usage_plan_keys(session, regions):
    total_usage_plan_keys = 0
    global_resource_tracker = set()
    
    for region in regions:
        client = session.client('apigateway', region_name=region)
        
        try:
            paginator = client.get_paginator('get_usage_plans')
            for page in paginator.paginate():
                for usage_plan in page['items']:
                    usage_plan_id = usage_plan['id']
                    
                    key_paginator = client.get_paginator('get_usage_plan_keys')
                    for key_page in key_paginator.paginate(usagePlanId=usage_plan_id):
                        for key in key_page['items']:
                            # Exclude resources managed by AWS
                            if 'aws' not in key['name'].lower():
                                if key['id'] not in global_resource_tracker:
                                    global_resource_tracker.add(key['id'])
                                    total_usage_plan_keys += 1
        except Exception as e:
            print(f"Error processing region {region}: {str(e)}")
    
    return total_usage_plan_keys

def aws_api_gateway_vpc_link(session, regions):
    """
    Counts the total number of non-AWS managed API Gateway VPC Links across all specified AWS regions.
    
    :param session: Boto3 session object
    :param regions: List of AWS regions to check
    
    :return: Total count of non-AWS managed API Gateway VPC Links
    """
    api_gateway_vpc_link_count = 0

    for region in regions:
        client = session.client('apigateway', region_name=region)
        
        paginator = client.get_paginator('get_vpc_links')
        for page in paginator.paginate():
            vpc_links = page.get('items', [])
            
            for vpc_link in vpc_links:
                if not vpc_link.get('name', '').startswith('AWS_'):
                    api_gateway_vpc_link_count += 1

    return api_gateway_vpc_link_count

def aws_apigatewayv2_api(session, regions):
    total_count = 0
    seen_apis = set()

    for region in regions:
        client = session.client('apigatewayv2', region_name=region)
        paginator = client.get_paginator('get_apis')
        for page in paginator.paginate():
            for api in page['Items']:
                api_id = api['ApiId']
                # Exclude resources created and managed by AWS
                if not api.get('ApiGatewayManaged') and api_id not in seen_apis:
                    seen_apis.add(api_id)
                    total_count += 1

    return total_count

def aws_apigatewayv2_api_mapping(session, regions):
    total_mappings_count = 0
    unique_mappings = set()

    for region in regions:
        # Create a client for the API Gateway V2 service
        client = session.client('apigatewayv2', region_name=region)
        
        # Get the list of API mappings in the current region
        try:
            response = client.get_api_mappings()
            api_mappings = response.get('Items', [])

            while 'NextToken' in response:
                response = client.get_api_mappings(NextToken=response['NextToken'])
                api_mappings.extend(response.get('Items', []))
            
            # Process each mapping in the current region
            for mapping in api_mappings:
                if not mapping['ApiMappingId'].startswith('aws'):
                    mapping_identifier = (mapping['ApiMappingId'], mapping['Stage'], mapping['ApiId'])
                    if mapping_identifier not in unique_mappings:
                        unique_mappings.add(mapping_identifier)
                        total_mappings_count += 1
        
        except Exception as e:
            print(f"An error occurred in region {region}: {str(e)}")

    return total_mappings_count

def aws_apigatewayv2_authorizer(session, regions):
    total_authorizers = 0
    
    for region in regions:
        client = session.client('apigatewayv2', region_name=region)
        
        paginator = client.get_paginator('get_authorizers')
        page_iterator = paginator.paginate()
        
        for page in page_iterator:
            for authorizer in page.get('Items', []):
                if not authorizer.get('ManagedByAws', False):
                    total_authorizers += 1
    
    return total_authorizers

def aws_apigatewayv2_deployment(session, regions):
    total_deployments = 0
    counted_global_resources = set()

    for region in regions:
        apigatewayv2_client = session.client('apigatewayv2', region_name=region)
        
        paginator = apigatewayv2_client.get_paginator('get_deployments')
        api_paginator = apigatewayv2_client.get_paginator('get_apis')
        
        for api_page in api_paginator.paginate():
            apis = api_page['Items']
            for api in apis:
                for page in paginator.paginate(ApiId=api['ApiId']):
                    deployments = page['Items']
                    for deployment in deployments:
                        if 'ManagedBy' not in deployment or deployment['ManagedBy'] != 'AWS':
                            if deployment['DeploymentId'] not in counted_global_resources:
                                counted_global_resources.add(deployment['DeploymentId'])
                                total_deployments += 1
                                
    return total_deployments

def aws_apigatewayv2_domain_name(session, regions):
    def is_managed_by_aws(domain_name):
        # Placeholder for logic to determine if domain name is managed by AWS.
        # Adjust the logic here based on actual naming convention or tags.
        return domain_name.get('DomainNameConfiguration', {}).get('Name', '').startswith('aws-')
    
    total_custom_domain_names = 0
    seen_domains = set()  # To keep track of global resources to count only once

    for region in regions:
        client = session.client('apigatewayv2', region_name=region)
        paginator = client.get_paginator('get_domain_names')
        page_iterator = paginator.paginate()

        for page in page_iterator:
            domain_names = page['Items']
            for domain in domain_names:
                domain_name = domain['DomainName']
                if not is_managed_by_aws(domain):
                    if domain_name not in seen_domains:
                        seen_domains.add(domain_name)
                        total_custom_domain_names += 1

    return total_custom_domain_names

def aws_apigatewayv2_integration(session, regions):
    def is_managed_by_aws(tags):
        return any(tag['Key'].startswith('aws:') for tag in tags)
    
    def get_integrations(client):
        integrations = []
        paginator = client.get_paginator('get_integrations')
        for page in paginator.paginate():
            if 'Items' in page:
                integrations.extend(page['Items'])
        return integrations
    
    total_count = 0
    seen_integrations = set()

    for region in regions:
        client = session.client('apigatewayv2', region_name=region)
        
        try:
            apis = client.get_apis()['Items']
            for api in apis:
                api_id = api['ApiId']
                paginator = client.get_paginator('get_integrations')
                
                for page in paginator.paginate(ApiId=api_id):
                    for integration in page.get('Items', []):
                        integration_id = integration['IntegrationId']
                        response = client.get_integration(ApiId=api_id, IntegrationId=integration_id)
                        integration_tags = response.get('Tags', {})
                        
                        if not is_managed_by_aws(integration_tags):
                            if integration_id not in seen_integrations:
                                seen_integrations.add(integration_id)
                                total_count += 1
        except client.exceptions.ThrottlingException as e:
            print(f"ThrottlingException encountered: {e}")
            continue
        except client.exceptions.ServiceQuotaExceededException as e:
            print(f"ServiceQuotaExceededException encountered: {e}")
            continue
        except Exception as e:
            print(f"Error encountered in region {region}: {e}")
            continue
    
    return total_count

def aws_apigatewayv2_model(session, regions):
    # Storing the total count of APIGatewayV2 models
    total_count = 0
    # A set to store global resource ids to ensure they are counted only once
    global_resources = set()

    for region in regions:
        # Creating a client for the given region
        client = session.client('apigatewayv2', region_name=region)

        # Retrieving a list of all existing API ids
        paginator = client.get_paginator('get_apis')
        for page in paginator.paginate():
            api_ids = [api['ApiId'] for api in page['Items']]
            for api_id in api_ids:
                # Retrieving the models for each API id
                models_paginator = client.get_paginator('get_models')
                for models_page in models_paginator.paginate(ApiId=api_id):
                    models = models_page['Items']
                    
                    for model in models:
                        # Check if the model is managed by AWS
                        if 'managed' not in model or not model['managed']:
                            # Use model identifier (name or id) to account for global uniqueness
                            model_identifier = model['Name']  # Assuming 'Name' or could be 'ModelId'
                            if model_identifier not in global_resources:
                                total_count += 1
                                global_resources.add(model_identifier)

    return total_count

def aws_apigatewayv2_route(session, regions):
    # Create an empty set to store unique resource ARNs
    unique_resources = set()
    
    # Iterate over each region
    for region in regions:
        # Get the APIGatewayV2 client for the specified region
        client = session.client('apigatewayv2', region_name=region)
        
        # Pagination for list_apis to handle large numbers of APIs
        paginator = client.get_paginator('get_apis')
        for page in paginator.paginate():
            for api in page['Items']:
                api_id = api['ApiId']
                
                # Get routes for each API
                routes_paginator = client.get_paginator('get_routes')
                for routes_page in routes_paginator.paginate(ApiId=api_id):
                    for route in routes_page['Items']:
                        # Check if the route is customer-managed, i.e., not managed by AWS
                        if not route.get('ManagedByAWS', False):
                            unique_resources.add(route['RouteId'])
    
    # Return the count of unique, customer-managed resources
    return len(unique_resources)

def aws_apigatewayv2_stage(session, regions):
    api_gateway_v2_stage_count = 0
    resource_prefix = 'aws:'  # Prefix for AWS-managed resources

    for region in regions:
        client = session.client('apigatewayv2', region_name=region)
        paginator = client.get_paginator('get_stages')

        for page in paginator.paginate():
            for stage in page['Items']:
                if not stage['StageName'].startswith(resource_prefix):
                    api_gateway_v2_stage_count += 1

    return api_gateway_v2_stage_count

def aws_apigatewayv2_vpc_link(session, regions):
    total_count = 0
    global_vpc_links = set()

    for region in regions:
        apigatewayv2_client = session.client('apigatewayv2', region_name=region)
        paginator = apigatewayv2_client.get_paginator('get_vpc_links')
        
        for page in paginator.paginate():
            for vpc_link in page['Items']:
                # Exclude any resources managed by AWS
                if 'arn:aws:' in vpc_link['VpcLinkId'] and 'CreatedByService' in vpc_link['Tags']:
                    continue
                
                global_resource_id = vpc_link['VpcLinkId']
                if global_resource_id not in global_vpc_links:
                    global_vpc_links.add(global_resource_id)
                    total_count += 1

    return total_count

def aws_appconfig_application(session, regions):
    appconfig_count = 0
    global_application_ids = set()
    
    for region in regions:
        client = session.client('appconfig', region_name=region)
        paginator = client.get_paginator('list_applications')
        
        for page in paginator.paginate():
            for application in page['Items']:
                if 'Tags' in application and 'aws-managed' in application['Tags']:
                    continue
                
                app_id = application['Id']
                
                if application['IsGlobal']:
                    if app_id not in global_application_ids:
                        global_application_ids.add(app_id)
                        appconfig_count += 1
                else:
                    appconfig_count += 1
    
    return appconfig_count

def aws_appmesh_mesh(session, regions):
    """
    Count the total number of aws_appmesh_mesh across all provided regions, excluding AWS managed resources.
    
    :param session: Existing boto3 session.
    :param regions: List of AWS regions to search in.
    :return: Total count of AWS App Mesh meshes, excluding AWS managed resources.
    """
    total_mesh_count = 0

    for region in regions:
        client = session.client('appmesh', region_name=region)
        paginator = client.get_paginator('list_meshes')
        for page in paginator.paginate():
            for mesh in page['meshes']:
                if 'aws:' not in mesh['meshName']:  # Exclude AWS managed resources
                    total_mesh_count += 1
                    
    return total_mesh_count

def aws_appmesh_virtual_gateway(session, regions):
    
    

    def is_aws_managed(resource_arn):
        # A function to check if a resource is AWS managed
        # This is just a placeholder for actual logic to determine AWS managed resources.
        aws_managed_prefixes = [
            "arn:aws:iam::aws:policy/",
            "arn:aws:cloudformation:aws:",
            # any other known AWS managed prefixes
        ]
        return any(resource_arn.startswith(prefix) for prefix in aws_managed_prefixes)

    total_virtual_gateways = 0
    seen_resources = set()
    
    for region in regions:
        try:
            client = session.client('appmesh', region_name=region)
            paginator = client.get_paginator('list_virtual_gateways')
            for page in paginator.paginate():
                for vg in page.get('virtualGateways', []):
                    if not is_aws_managed(vg.get('resourceArn')) and vg.get('resourceArn') not in seen_resources:
                        total_virtual_gateways += 1
                        seen_resources.add(vg.get('resourceArn'))
        except ClientError as e:
            print(f"An error occurred: {e}")

    return total_virtual_gateways

def aws_appmesh_virtual_node(session, regions):
    
    

    def is_managed_by_aws(tags):
        for tag in tags:
            if ('aws' in tag.get('Key', '').lower()) or ('aws' in tag.get('Value', '').lower()):
                return True
        return False

    total_virtual_nodes = 0
    for region in regions:
        try:
            appmesh_client = session.client('appmesh', region_name=region)
            
            # List all service meshes in the region
            meshes = appmesh_client.list_meshes()['meshes']

            for mesh in meshes:
                mesh_name = mesh['meshName']

                virtual_nodes = appmesh_client.list_virtual_nodes(meshName=mesh_name)['virtualNodes']

                for virtual_node in virtual_nodes:
                    virtual_node_name = virtual_node['virtualNodeName']
                    tags = appmesh_client.list_tags_for_resource(
                        resourceArn=virtual_node['arn']
                    ).get('tags', [])

                    if not is_managed_by_aws(tags):
                        total_virtual_nodes += 1
                        
        except ClientError as e:
            print(f"An error occurred in region {region}: {e}")

    return total_virtual_nodes

def aws_appmesh_virtual_router(session, regions):
    """
    Count the total number of AWS App Mesh Virtual Routers across all provided regions,
    excluding those that are created and managed by AWS.

    Parameters:
    session (boto3.Session): An existing Boto3 session.
    regions (list): A list of AWS regions to check.

    Returns:
    int: The total count of App Mesh Virtual Routers across the regions.
    """
    total_count = 0
    exclusion_prefix = 'aws'

    for region in regions:
        appmesh = session.client('appmesh', region_name=region)
        meshes = appmesh.list_meshes()

        for mesh in meshes['meshes']:
            mesh_name = mesh['meshName']
            virtual_routers = appmesh.list_virtual_routers(meshName=mesh_name)

            for vr in virtual_routers['virtualRouters']:
                vr_name = vr['virtualRouterName']
                if not vr_name.lower().startswith(exclusion_prefix):
                    total_count += 1
                
    return total_count

def aws_appmesh_virtual_service(session, regions):
    
    
    appmesh_client = session.client('appmesh')
    
    total_virtual_services = 0

    for region in regions:
        regional_client = session.client('appmesh', region_name=region)
        paginator = regional_client.get_paginator('list_virtual_services')
        response_iterator = paginator.paginate()
        
        for response in response_iterator:
            for virtual_service in response['virtualServices']:
                arn = virtual_service['metadata']['arn']
                if not arn.startswith('arn:aws:appmesh:'):
                    total_virtual_services += 1
                    
    return total_virtual_services

def aws_athena_data_catalog(session, regions):
    """
    This function counts the total number of AWS Athena Data Catalogs across all regions,
    excluding any resources that are created and managed by AWS. It ensures that global
    resources are only counted once.
    
    :param session: An existing boto3 session object.
    :param regions: An array of AWS regions.
    :return: The total number of AWS Athena Data Catalogs.
    """
    athena = session.client('athena')
    total_count = 0
    
    for region in regions:
        athena = session.client('athena', region_name=region)
        response = athena.list_data_catalogs()
        for catalog in response['DataCatalogsSummary']:
            if catalog['Type'] != 'GLUE':  # Exclude managed AWS Glue Data Catalog
                total_count += 1
    
    return total_count

def aws_athena_database(session, regions):
    """
    Counts the total number of Athena databases across all specified regions, excluding any
    resources that are created and managed by AWS.
    
    Parameters:
        session (boto3.session.Session): The boto3 session object.
        regions (list): List of AWS regions as strings.
    
    Returns:
        int: Total count of Athena databases excluding AWS-managed ones.
    """
    counts = {}

    for region in regions:
        athena = session.client('athena', region_name=region)
        response = athena.list_databases(CatalogName='AwsDataCatalog')
        databases = response.get('DatabaseList', [])

        for db in databases:
            # Exclude AWS-managed databases
            if not db['Name'].startswith('aws_'):
                counts[db['Name']] = counts.get(db['Name'], 0) + 1
                
    return len(counts)

def aws_athena_named_query(session, regions):
    athena_named_query_count = 0
    seen_resource_ids = set()  # To ensure global resources are counted only once

    for region in regions:
        client = session.client('athena', region_name=region)
        paginator = client.get_paginator('list_named_queries')
        for page in paginator.paginate():
            for query_id in page['NamedQueryIds']:
                # Exclusion logic for AWS managed resources goes here
                if query_id not in seen_resource_ids:
                    seen_resource_ids.add(query_id)
                    athena_named_query_count += 1

    return athena_named_query_count

def aws_athena_workgroup(session, regions):
    """
    Count the total number of AWS Athena workgroups across all specified regions, 
    excluding those created and managed by AWS. Global resources are counted once.

    :param session: Existing boto3 session.
    :param regions: List of AWS regions to check.
    :return: Total count of non-AWS-managed Athena workgroups across the specified regions.
    """
    total_workgroups = set()  # Using set to handle global resources only once

    for region in regions:
        client = session.client('athena', region_name=region)
        response = client.list_work_groups()
        for workgroup in response['WorkGroups']:
            if not workgroup['Name'].startswith('aws:'):
                total_workgroups.add(workgroup['Name'])

    return len(total_workgroups)

def aws_autoscaling_group(session, regions):
    total_asg_count = 0

    for region in regions:
        client = session.client('autoscaling', region_name=region)
        paginator = client.get_paginator('describe_auto_scaling_groups')
        
        for page in paginator.paginate():
            for group in page['AutoScalingGroups']:
                # Exclude ASGs managed by AWS
                total_asg_count += 1

    return total_asg_count

def aws_autoscaling_lifecycle_hook(session, regions):
    total_hooks_count = 0
    resource_name_prefix = "aws:" # AWS managed resources prefix
    
    for region in regions:
        client = session.client('autoscaling', region_name=region)
        paginator = client.get_paginator('describe_lifecycle_hooks')
        
        for page in paginator.paginate():
            for lifecycle_hook in page['LifecycleHooks']:
                hook_name = lifecycle_hook['LifecycleHookName']
                if not hook_name.startswith(resource_name_prefix):
                    total_hooks_count += 1
    
    return total_hooks_count

def aws_autoscaling_policy(session, regions):
    

    def is_managed_by_aws(policy_name):
        aws_managed_prefixes = ["aws", "eks", "elasticache", "kinesis", "cloudfront"]
        return any(policy_name.lower().startswith(prefix) for prefix in aws_managed_prefixes)

    total_autoscaling_policies = 0
    seen_policy_arns = set()

    for region in regions:
        autoscaling_client = session.client('autoscaling', region_name=region)
        paginator = autoscaling_client.get_paginator('describe_policies')
        
        for page in paginator.paginate():
            for policy in page['ScalingPolicies']:
                policy_arn = policy['PolicyARN']
                
                if policy_arn not in seen_policy_arns and not is_managed_by_aws(policy['PolicyName']):
                    seen_policy_arns.add(policy_arn)
                    total_autoscaling_policies += 1

    return total_autoscaling_policies

def aws_backup_vault(session, regions):
    backup_vault_set = set()

    for region in regions:
        client = session.client('backup', region_name=region)
        response = client.list_backup_vaults()
        
        for vault in response['BackupVaultList']:
            vault_name = vault['BackupVaultName']
            
            # Exclude resources that are created and managed by AWS
            if not vault_name.startswith('aws/'):
                backup_vault_set.add(vault_name)
        
    return len(backup_vault_set)

# def aws_cloudfront_cache_policy(session, regions):
    
#     count = 0
#     unique_policies = set()

#     for region in regions:
#         cf_client = session.client('cloudfront', region_name=region)
        
#         paginator = cf_client.get_paginator('list_cache_policies')
#         page_iterator = paginator.paginate()
        
#         for page in page_iterator:
#             for policy in page.get('CachePolicyList', {}).get('Items', []):
#                 policy_id = policy.get('CachePolicy', {}).get('Id')
#                 owned_by_aws = policy.get('CachePolicy', {}).get('LastModifiedTime').startswith('AWS')
                
#                 if policy_id and not owned_by_aws:
#                     unique_policies.add(policy_id)

#     # Return the number of unique cache policies across all regions
#     return len(unique_policies)

def aws_cloudfront_cache_policy(session, regions):
    
    unique_policies = set()

    for region in regions:
        cf_client = session.client('cloudfront', region_name=region)
        
        # Directly call the list_cache_policies method
        response = cf_client.list_cache_policies()
        
        for policy in response.get('CachePolicyList', {}).get('Items', []):
            policy_id = policy.get('CachePolicy', {}).get('Id')
                    
            if policy_id:
                unique_policies.add(policy_id)

    # Return the number of unique cache policies across all regions
    return len(unique_policies)

def aws_cloudfront_distribution(session, regions):
    cloudfront_client = session.client('cloudfront')
    # CloudFront is a global service, it is not region-specific.
    paginator = cloudfront_client.get_paginator('list_distributions')

    total_distributions = 0

    for page in paginator.paginate():
        if 'Items' in page['DistributionList']:
            for distribution in page['DistributionList']['Items']:
                if 'AWS' not in distribution['Comment']:
                    total_distributions += 1

    return total_distributions

def aws_cloudfront_function(session, regions):
    cloudfront_client = session.client('cloudfront')
    global_resources = set()
    regional_counts = {}

    # Count global resources (CloudFront is a global service)
    distributions = cloudfront_client.list_distributions()
    if distributions['DistributionList']['Quantity'] > 0:
        for distribution in distributions['DistributionList']['Items']:
            if 'AWS' not in distribution['Origins']['Items'][0]['DomainName']:
                global_resources.add(distribution['Id'])
    
    # Count regional resources
    for region in regions:
        client = session.client('servicequotas', region_name=region)
        quota = client.get_service_quota(
            ServiceCode='cloudfront',
            QuotaCode='L-<Service-Quota-Code>'
        )
        regional_counts[region] = quota['Quota']['Value']

    total_count = len(global_resources) + sum(regional_counts.values())
    
    return total_count

def aws_cloudfront_key_group(session, regions):
    cloudfront_client = session.client('cloudfront')
    paginator = cloudfront_client.get_paginator('list_key_groups')

    total_count = 0
    unique_global_resources = set()

    for region in regions:
        region_client = session.client('cloudfront', region_name=region)
        
        for page in paginator.paginate():
            for key_group in page['KeyGroupList']['Items']:
                # Exclude managed resources by AWS
                if not key_group['KeyGroupConfig']['Name'].startswith('aws_'):
                    key_group_id = key_group['Id']
                    
                    # Since CloudFront is global, let's ensure we only count unique key groups
                    if key_group_id not in unique_global_resources:
                        unique_global_resources.add(key_group_id)
                        total_count += 1
    
    return total_count

def aws_cloudfront_origin_access_identity(session, regions):
    total_count = 0
    cf_client = session.client('cloudfront')

    # CloudFront is a global service, so we only need to list origin access identities once
    try:
        response = cf_client.list_cloud_front_origin_access_identities()
        for item in response['CloudFrontOriginAccessIdentityList']['Items']:
            if 'Self-AWSManaged' in item['Comment']:
                continue
            total_count += 1
    except Exception as e:
        print(f"Error listing CloudFront Origin Access Identities: {e}")
    
    return total_count

# def aws_cloudfront_origin_request_policy(session, region):
    
    
#     def list_origin_request_policies(client):
#         try:
#             policies = []
#             paginator = client.get_paginator('list_origin_request_policies')
#             for page in paginator.paginate(Type='custom'):
#                 policies.extend(page.get('OriginRequestPolicyList', {}).get('Items', []))
#             return policies
#         except client.exceptions.AccessDeniedException:
#             return []
    
#     # Initialize AWS CloudFront client in a global region
#     cloudfront_client_global = session.client('cloudfront')
    
#     # Fetch all CloudFront Origin Request Policies created by users (not AWS)
#     all_policies = list_origin_request_policies(cloudfront_client_global)
    
#     # Since CloudFront resources are global, we don't need to iterate over each region
#     user_created_policies = all_policies

#     # Return the count of user-created CloudFront Origin Request Policies
#     return len(user_created_policies)

def aws_cloudfront_origin_request_policy(session, regions):
    def list_origin_request_policies(client):
        try:
            policies = []
            response = client.list_origin_request_policies()
            policies.extend(response.get('OriginRequestPolicyList', {}).get('Items', []))
            return policies
        except client.exceptions.AccessDeniedException:
            return []
    
    # Initialize AWS CloudFront client (CloudFront is a global service)
    cloudfront_client_global = session.client('cloudfront')
    
    # Fetch all CloudFront Origin Request Policies
    all_policies = list_origin_request_policies(cloudfront_client_global)
    
    # Filter out policies created by AWS (assuming an attribute for filtering, adjust as needed)
    user_created_policies = [
        policy for policy in all_policies
        if not policy['OriginRequestPolicyConfig']['Name'].startswith('aws:')
    ]

    # Return the count of user-created CloudFront Origin Request Policies
    return len(user_created_policies)

def aws_cloudfront_realtime_log_config(session, regions):
    cloudfront_client = session.client('cloudfront')
    excluded_managed_by_aws = ['AWSManaged']  # Example values, adjust as needed
    total_realtime_log_configs = 0

    # CloudFront is a global service, so we only need to list configurations once
    response = cloudfront_client.list_realtime_log_configs()

    # Count the real-time log configurations excluding the ones managed by AWS
    for log_config in response.get('RealtimeLogConfigs', []):
        # Assuming that log configs managed by AWS may have identifiable tags or markers
        if log_config['ARN'].split(':')[5].startswith('AWS'):
            continue
        total_realtime_log_configs += 1

    return total_realtime_log_configs

def aws_cloudhsm_v2_cluster(session, regions):
    client = session.client('cloudhsmv2')
    total_clusters = 0

    for region in regions:
        regional_client = session.client('cloudhsmv2', region_name=region)
        clusters = regional_client.describe_clusters()
        user_managed_clusters = [
            cluster for cluster in clusters['Clusters'] if not cluster['TagList'] or not any(tag['Key'] == 'aws:cloudformation:stack-name' for tag in cluster['TagList'])
        ]
        total_clusters += len(user_managed_clusters)

    return total_clusters

def aws_cloudhsm_v2_hsm(session, regions):
    

    def get_hsm_count_in_region(region_name):
        hsm_client = session.client('cloudhsmv2', region_name=region_name)
        hsm_count = 0
        try:
            clusters = hsm_client.describe_clusters()['Clusters']
            for cluster in clusters:
                hsm_count += len(cluster['Hsms'])
        except Exception as e:
            print(f"Error fetching HSMs in region {region_name}: {e}")
        return hsm_count

    total_hsm_count = 0
    for region in regions:
        total_hsm_count += get_hsm_count_in_region(region)

    return total_hsm_count

def aws_cloudtrail(session, regions):
    """
    Count the total number of AWS CloudTrail trails across all regions,
    excluding those that are AWS-managed (created and managed by AWS).
    
    :param session: boto3 Session object
    :param regions: List of AWS regions to check
    :return: Total count of CloudTrails
    """
    trails_seen = set()  # To avoid counting global resources more than once

    total_count = 0
    
    for region in regions:
        regional_client = session.client('cloudtrail', region_name=region)
        
        try:
            response = regional_client.describe_trails()
            trails = response.get('trailList', [])
            
            for trail in trails:
                trail_arn = trail['TrailARN']
                
                # Skip if already seen (global resource check)
                if trail_arn in trails_seen:
                    continue
                
                # Skip AWS-managed trails
                if trail.get('IsOrganizationTrail', False):
                    continue
                
                trails_seen.add(trail_arn)
                total_count += 1

        except ClientError as e:
            print(f"Error querying CloudTrail in region {region}: {e}")
    
    return total_count
    
def aws_cloudwatch_composite_alarm(session, regions):
    total_alarms = set()
    
    def get_alarms_in_region(region):
        cloudwatch_client = session.client('cloudwatch', region_name=region)
        paginator = cloudwatch_client.get_paginator('describe_alarms')
        alarms = set()
        
        for page in paginator.paginate(AlarmTypes=['CompositeAlarm']):
            for alarm in page['CompositeAlarms']:
                if not alarm['AlarmName'].startswith('AWS/'):
                    alarms.add(alarm['AlarmArn'])
        
        return alarms
    
    for region in regions:
        alarms_in_region = get_alarms_in_region(region)
        total_alarms.update(alarms_in_region)
    
    return len(total_alarms)

def aws_cloudwatch_dashboard(session, regions):

    def count_dashboards_in_region(region_name):
        client = session.client('cloudwatch', region_name=region_name)
        paginator = client.get_paginator('list_dashboards')
        count = 0

        for page in paginator.paginate():
            for dashboard in page['DashboardEntries']:
                # Exclude AWS managed dashboards by checking for a specific naming pattern
                if not (dashboard['DashboardName'].startswith('AWS/') or 
                        dashboard['DashboardName'].startswith('Amazon/')):
                    count += 1

        return count

    total_count = 0
    for region in regions:
        total_count += count_dashboards_in_region(region)

    return total_count

def aws_cloudwatch_event_bus(session, regions):
    

    total_event_buses = 0
    global_event_buses = set()
    
    for region in regions:
        # Create a CloudWatch client for the specified region
        client = session.client('events', region_name=region)
        
        # List all event buses in the current region
        response = client.list_event_buses()
        for event_bus in response.get('EventBuses', []):
            event_bus_name = event_bus['Name']
            
            # Skip event buses that are created and managed by AWS
            if not event_bus_name.startswith('aws.'):
                # Consider the global event buses which appear in every region
                if event_bus_name not in global_event_buses:
                    global_event_buses.add(event_bus_name)
                    total_event_buses += 1

    return total_event_buses

def aws_cloudwatch_event_rule(session, regions):
    
    
    # Create a list to store unique event rule ARNs
    unique_event_rules = set()
    
    for region in regions:
        client = session.client('events', region_name=region)
        
        # Paginate through the list of event rules
        paginator = client.get_paginator('list_rules')
        response_iterator = paginator.paginate()
        
        for page in response_iterator:
            for rule in page['Rules']:
                rule_arn = rule['Arn']
                
                # Skip managed by AWS event rules
                unique_event_rules.add(rule_arn)
    
    # Return the total count of unique event rules
    return len(unique_event_rules)

def aws_cloudwatch_event_target(session, regions):
    try:
        total_targets = 0
        counted_global = set()
        
        for region in regions:
            client = session.client('events', region_name=region)
            paginator = client.get_paginator('list_rules')
            for page in paginator.paginate():
                for rule in page['Rules']:
                    rule_arn = rule['Arn']
                    
                    # Skips rules managed by AWS

                    # Count global resources only once
                    if rule['EventBusName'].lower() == 'default':
                        if rule_arn in counted_global:
                            continue
                        else:
                            counted_global.add(rule_arn)
                    
                    response = client.list_targets_by_rule(Rule=rule['Name'])
                    total_targets += len(response['Targets'])
        
        return total_targets
    
    except Exception as e:
        print("An error occurred:", str(e))
        return 0

def aws_cloudwatch_log_group(session, regions):
    
    
    def is_managed_by_aws(log_group_name):
        # Modify this condition if there's a more specific pattern to detect AWS-managed log groups
        return log_group_name.startswith('/aws/')
    
    total_log_groups = set()
    
    for region in regions:
        # Create CloudWatch Logs client for the region
        logs_client = session.client('logs', region_name=region)
        
        # Paginate through log groups (since there can be more than 50 log groups)
        paginator = logs_client.get_paginator('describe_log_groups')
        for page in paginator.paginate():
            for log_group in page['logGroups']:
                log_group_name = log_group['logGroupName']
                if not is_managed_by_aws(log_group_name):
                    total_log_groups.add(log_group_name)
    
    return len(total_log_groups)

def aws_cloudwatch_log_subscription_filter(session, regions):
    log_client = session.client('logs')
    
    total_subscription_filters = 0
    managed_by_aws_prefix = 'AWS'

    for region in regions:
        regional_client = session.client('logs', region_name=region)
        
        paginator = regional_client.get_paginator('describe_subscription_filters')

        for page in paginator.paginate():
            for subscription_filter in page['subscriptionFilters']:
                if not subscription_filter['filterName'].startswith(managed_by_aws_prefix):
                    total_subscription_filters += 1

    return total_subscription_filters

def aws_cloudwatch_metric_alarm(session, regions):
    global_resources = set()
    total_alarms = 0
    
    for region in regions:
        try:
            cloudwatch_client = session.client('cloudwatch', region_name=region)
            paginator = cloudwatch_client.get_paginator('describe_alarms')
            
            for page in paginator.paginate():
                for alarm in page['MetricAlarms']:
                    alarm_name = alarm['AlarmName']
                    
                    if not is_aws_managed_resource(alarm_name):
                        if alarm_name not in global_resources:
                            global_resources.add(alarm_name)
                            total_alarms += 1
                        
        except Exception as e:
            print(f"Error in region {region}: {e}")
    
    return total_alarms

def is_aws_managed_resource(resource_name):
    # This function should define the logic to determine if a resource is managed by AWS
    # For the purpose of this example, we assume AWS managed resources have a specific naming pattern
    aws_managed_patterns = ["AWS/", "AWSElasticBeanstalk-", "AWS-", "AWS/"]
    
    for pattern in aws_managed_patterns:
        if resource_name.startswith(pattern):
            return True
    return False

def aws_cloudwatch_metric_stream(session, regions):
    cloudwatch_metric_stream_count = 0
    seen_global_resources = set()

    for region in regions:
        client = session.client('cloudwatch', region_name=region)
        paginator = client.get_paginator('list_metric_streams')
        
        for page in paginator.paginate():
            for stream in page['MetricStreams']:
                if not stream['Arn'].startswith('arn:aws:cloudwatch:aws'):
                    cloudwatch_metric_stream_count += 1

    return cloudwatch_metric_stream_count

def aws_codebuild_project(session, regions):
    """
    This function counts the total number of AWS CodeBuild projects across all specified regions,
    excluding projects created and managed by AWS.

    :param session: The existing boto3 session.
    :param regions: Array of AWS regions to be considered.
    :return: Total number of user-created AWS CodeBuild projects.
    """
    

    total_projects = 0

    for region in regions:
        try:
            client = session.client('codebuild', region_name=region)
            paginator = client.get_paginator('list_projects')
            for page in paginator.paginate():
                for project_name in page['projects']:
                    project_info = client.batch_get_projects(names=[project_name])['projects'][0]
                    if not project_info['name'].startswith('aws-'):
                        total_projects += 1
        except ClientError as e:
            print(f"Error occurred in region {region}: {e}")

    return total_projects

    def is_managed_by_aws(name):
        # Changes in naming conventions can be applied here if necessary
        return name.startswith('AWS')

    total_report_groups = set()

    for region in regions:
        codebuild_client = session.client('codebuild', region_name=region)
        
        paginator = codebuild_client.get_paginator('list_report_groups')
        for page in paginator.paginate():
            for report_group in page['reportGroups']:
                if not is_managed_by_aws(report_group):
                    total_report_groups.add(report_group)

    return len(total_report_groups)

def aws_codepipeline(session, regions):
    """
    Count the total number of AWS CodePipeline pipelines across all specified regions,
    excluding any that are created and managed by AWS.
    
    Args:
        session (boto3.session.Session): An existing boto3 session.
        regions (list): A list of AWS regions to check.
        
    Returns:
        int: The total number of user-created AWS CodePipeline pipelines.
    """
    excluded_prefixes = ["aws-"]  # Add other prefixes if there are more AWS managed pipelines
    total_count = 0
    
    for region in regions:
        cp_client = session.client('codepipeline', region_name=region)
        
        paginator = cp_client.get_paginator('list_pipelines')
        for page in paginator.paginate():
            for pipeline in page['pipelines']:
                # Check if pipeline name starts with any of the excluded prefixes
                if not any(pipeline['name'].startswith(prefix) for prefix in excluded_prefixes):
                    total_count += 1
    
    return total_count

def aws_codepipeline_webhook(session, regions):
    

    # Function to count webhooks in a single region
    def count_webhooks_for_region(region_name, session):
        client = session.client('codepipeline', region_name=region_name)
        paginator = client.get_paginator('list_webhooks')
        count = 0
        for page in paginator.paginate():
            for webhook in page['webhooks']:
                # Check the definition of AWS managed resources and skip them
                if not webhook['definition'].get('source', {}).get('owner') == 'AWS':
                    count += 1
        return count
    
    # Get unique global resources
    unique_webhooks = set()

    # Count the webhooks in all regions
    total_count = 0
    for region in regions:
        total_count += count_webhooks_for_region(region, session)
        
    return total_count

def aws_cognito_identity_pool(session, regions):
    cognito = session.client('cognito-identity')
    total_pools = 0

    global_identity_pools = set()  # To ensure global resources are only counted once

    for region in regions:
        regional_cognito = session.client('cognito-identity', region_name=region)
        paginator = regional_cognito.get_paginator('list_identity_pools')

        for page in paginator.paginate(MaxResults=60):
            for pool in page['IdentityPools']:
                # Assuming resources created and managed by AWS have 'AWS' in their name
                if 'AWS' not in pool['IdentityPoolName']:
                    # Use a set to avoid double-counting global resources
                    if pool['IdentityPoolId'] not in global_identity_pools:
                        global_identity_pools.add(pool['IdentityPoolId'])
                        total_pools += 1

    return total_pools

def aws_cognito_identity_provider(session, regions):
    """Counts the total number of Cognito identity providers across all regions, excluding AWS managed resources."""
    total_identity_providers = 0
    cognito_global_service_name = 'cognito-identity'  # Global service name for Cognito Identity
    
    # Function to check if a resource is AWS managed
    def is_aws_managed(identity_provider):
        return 'aws' in identity_provider

    for region in regions:
        # Create a client for the specific region
        cognito_idp_client = session.client('cognito-idp', region_name=region)
        
        paginator = cognito_idp_client.get_paginator('list_identity_providers')
        page_iterator = paginator.paginate(
            UserPoolId='YOUR_USER_POOL_ID'
        )
        
        for page in page_iterator:
            identity_providers = page.get('Providers', [])
            
            for identity_provider in identity_providers:
                if not is_aws_managed(identity_provider['ProviderName']):
                    total_identity_providers += 1

    return total_identity_providers

def aws_cognito_resource_server(session, regions):
    cognito_client = session.client('cognito-idp')
    total_resource_servers = 0
    seen_global_resources = set()

    for region in regions:
        cognito_client = session.client('cognito-idp', region_name=region)
        user_pools = cognito_client.list_user_pools(MaxResults=60)['UserPools']

        for pool in user_pools:
            user_pool_id = pool['Id']
            paginator = cognito_client.get_paginator('list_resource_servers')
            page_iterator = paginator.paginate(UserPoolId=user_pool_id)
            
            for page in page_iterator:
                for resource_server in page['ResourceServers']:
                    arn = resource_server['ResourceServerIdentifier']
                    if "AWSServiceAccessRolePolicy" not in arn:  # Exclude AWS-managed resources
                        resource_id = resource_server['Id']
                        if resource_id not in seen_global_resources:
                            seen_global_resources.add(resource_id)
                            total_resource_servers += 1
                        
    return total_resource_servers

def aws_cognito_user_group(session, regions):
    total_count = 0
    global_user_groups = set()

    try:
        for region in regions:
            cognito_client = session.client('cognito-idp', region_name=region)
            paginator = cognito_client.get_paginator('list_user_pools')
            
            for page in paginator.paginate(MaxResults=60):
                for user_pool in page['UserPools']:
                    user_pool_id = user_pool['Id']
                    user_pool_name = user_pool['Name']
                    
                    # Skip AWS created and managed resources
                    if user_pool_name.startswith("AWS"):
                        continue

                    describe_user_pool_response = cognito_client.describe_user_pool(UserPoolId=user_pool_id)
                    is_global = describe_user_pool_response['UserPool']['AliasAttributes']

                    if is_global:
                        global_user_groups.add(user_pool_id)
                    else:
                        group_paginator = cognito_client.get_paginator('list_groups')
                        for group_page in group_paginator.paginate(UserPoolId=user_pool_id):
                            total_count += len(group_page['Groups'])

        # Add the global user groups to the total count
        total_count += len(global_user_groups)
        
    except (NoCredentialsError, PartialCredentialsError) as e:
        return f"Error with AWS credentials: {str(e)}"
    except Exception as e:
        return f"An error occurred: {str(e)}"
    
    return total_count

def aws_cognito_user_pool(session, regions):
    """
    Count the total number of AWS Cognito user pools across all specified regions,
    excluding any resources that are created and managed by AWS.

    :param session: boto3.Session object
    :param regions: List of AWS region strings
    :return: Total count of user pools
    """
    total_user_pools = 0
    already_counted = set()

    for region in regions:
        cognito_client = session.client('cognito-idp', region_name=region)
        paginator = cognito_client.get_paginator('list_user_pools')
        
        for page in paginator.paginate(MaxResults=60):
            for user_pool in page['UserPools']:
                if user_pool['Id'] not in already_counted:
                    total_user_pools += 1
                    already_counted.add(user_pool['Id'])

    return total_user_pools

def aws_cognito_user_pool_client(session, regions):
    

    user_pool_client_count = 0
    seen_user_pool_clients = set()

    for region in regions:
        cognito_client = session.client('cognito-idp', region_name=region)
        try:
            paginator = cognito_client.get_paginator('list_user_pools')
            for page in paginator.paginate(MaxResults=60):
                for user_pool in page['UserPools']:
                    user_pool_id = user_pool['Id']
                    client_paginator = cognito_client.get_paginator('list_user_pool_clients')
                    for client_page in client_paginator.paginate(UserPoolId=user_pool_id, MaxResults=60):
                        for client in client_page['UserPoolClients']:
                            client_id = client['ClientId']
                            client_desc = cognito_client.describe_user_pool_client(
                                UserPoolId=user_pool_id,
                                ClientId=client_id
                            )['UserPoolClient']
                            
                            # Only count clients not created by AWS
                            if 'UserAgent' not in client_desc or not client_desc['UserAgent'].startswith('aws:'):
                                if client_id not in seen_user_pool_clients:
                                    seen_user_pool_clients.add(client_id)
                                    user_pool_client_count += 1
        except Exception as e:
            print(f"Error in region {region}: {str(e)}")

    return user_pool_client_count

def aws_config_aggregate_authorization(session, regions):
    """
    Counts the total number of AWS Config aggregate authorizations across all specified regions,
    excluding any resources that are created and managed by AWS. Ensures that global resources 
    are only counted once.

    :param session: Boto3 session
    :param regions: List of AWS regions to check
    :return: Integer count of AWS Config aggregate authorizations
    """
    config_client = session.client('config')
    total_count = 0
    global_resources_seen = set()

    for region in regions:
        regional_client = session.client('config', region_name=region)
        paginator = regional_client.get_paginator('describe_aggregate_authorizations')
        for page in paginator.paginate():
            for auth in page.get('AggregateAuthorizations', []):
                if not auth['CreationTime']:
                    continue  # Skip resources managed by AWS

                resource_identifier = auth['AggregatorName'] + auth['AccountId'] + auth['Region']
                if resource_identifier not in global_resources_seen:
                    global_resources_seen.add(resource_identifier)
                    total_count += 1

    return total_count

def aws_config_configuration_recorder(session, regions):
    total_recorders = 0
    global_recorder_ids = set()
    
    for region in regions:
        client = session.client('config', region_name=region)
        try:
            response = client.describe_configuration_recorders()
            recorders = response.get('ConfigurationRecorders', [])
            for recorder in recorders:
                recorder_name = recorder.get('name', '')
                # Exclude AWS-managed resources
                if not recorder_name.startswith('AWS'):
                    if recorder_name not in global_recorder_ids:
                        total_recorders += 1
                        global_recorder_ids.add(recorder_name)
        except client.exceptions.NoConfigurationRecorderException:
            continue
    
    return total_recorders

def aws_config_delivery_channel(session, regions):
    # Initialize a set for global resources to ensure they are counted only once
    global_resources = set()

    # Initialize a counter for the delivery channels
    total_delivery_channels = 0

    # Iterate through each specified region
    for region in regions:
        # Create a ConfigService client for the region
        config_client = session.client('config', region_name=region)
        
        # Get the delivery channels in the region
        response = config_client.describe_delivery_channels()

        for channel in response.get('DeliveryChannels', []):
            channel_name = channel.get('name', '')

            # Check if the channel is not managed by AWS
            if not channel_name.startswith('aws-'):
                # Check if it is a global resource and count if not already counted
                if region in ['us-east-1']:  # assuming global resources are typically created in 'us-east-1'
                    global_resources.add(channel_name)
                else:
                    total_delivery_channels += 1

    # Add the number of unique global resources
    total_delivery_channels += len(global_resources)

    return total_delivery_channels

def aws_db_cluster_snapshot(session, region):
    global_snapshots = set()
    total_count = 0
    
    for reg in region:
        rds_client = session.client('rds', region_name=reg)
        paginator = rds_client.get_paginator('describe_db_cluster_snapshots')
        
        for page in paginator.paginate():
            snapshots = page['DBClusterSnapshots']
            for snapshot in snapshots:
                if 'aws:' not in snapshot['DBClusterSnapshotIdentifier']:
                    if snapshot['DBClusterSnapshotArn'] not in global_snapshots:
                        global_snapshots.add(snapshot['DBClusterSnapshotArn'])
                        total_count += 1
    
    return total_count

def aws_db_event_subscription(session, regions):
    """
    Count the total number of AWS RDS event subscriptions across all specified regions,
    excluding those created and managed by AWS. Global resources are only counted once.

    :param session: boto3 session object.
    :param regions: list of AWS regions to check.
    :return: total count of user-managed AWS RDS event subscriptions.
    """
    seen_subscriptions = set()
    
    for region in regions:
        rds_client = session.client('rds', region_name=region)
        paginator = rds_client.get_paginator('describe_event_subscriptions')
        
        for page in paginator.paginate():
            for subscription in page['EventSubscriptionsList']:
                if 'aws:' not in subscription['CustSubscriptionId']:  # Exclude AWS managed
                    # Using a combination of subscription name and source type to handle global resources
                    subscription_key = (subscription['CustSubscriptionId'], subscription['SourceType'])
                    seen_subscriptions.add(subscription_key)
    
    total_count = len(seen_subscriptions)
    return total_count

def aws_db_instance(session, regions):
    global_db_instances = set()
    total_db_instances = 0

    for region in regions:
        rds_client = session.client('rds', region_name=region)

        # Describe instances in the region
        paginator = rds_client.get_paginator('describe_db_instances')
        for page in paginator.paginate():
            for db_instance in page['DBInstances']:
                # Exclude AWS managed resources using a typical naming pattern or identifier
                if not (db_instance['DBInstanceIdentifier'].startswith('rds:') or
                        db_instance['DBInstanceIdentifier'].startswith('aws:')):
                    instance_arn = db_instance['DBInstanceArn']
                    # RDS instances are regional resources, so just count them
                    total_db_instances += 1

    return total_db_instances

def aws_db_option_group(session, regions):
    client = session.client('rds')
    total_option_groups = 0
    global_option_groups = set()

    for region in regions:
        rds_client = session.client('rds', region_name=region)
        paginator = rds_client.get_paginator('describe_option_groups')
        response_iterator = paginator.paginate()

        for response in response_iterator:
            for option_group in response['OptionGroupsList']:
                if not option_group['OptionGroupArn'].startswith('arn:aws:rds:::'):
                    name = option_group['OptionGroupName']
                    
                    if option_group['OptionGroupArn'].split(':')[1] == 'global':
                        if name not in global_option_groups:
                            global_option_groups.add(name)
                            total_option_groups += 1
                    else:
                        total_option_groups += 1

    return total_option_groups

def aws_db_parameter_group(session, regions):
    def is_managed_by_aws(parameter_group_name):
        managed_prefixes = ['default.', 'aws.']
        return any(parameter_group_name.startswith(prefix) for prefix in managed_prefixes)
    
    total_count = 0
    seen_parameter_groups = set()

    for region in regions:
        rds_client = session.client('rds', region_name=region)
        paginator = rds_client.get_paginator('describe_db_parameter_groups')
        for page in paginator.paginate():
            for parameter_group in page['DBParameterGroups']:
                parameter_group_name = parameter_group['DBParameterGroupName']
                if not is_managed_by_aws(parameter_group_name):
                    if parameter_group_name not in seen_parameter_groups:
                        seen_parameter_groups.add(parameter_group_name)
                        total_count += 1
    
    return total_count

def aws_db_proxy(session, regions):
    """
    Count the total number of AWS DB Proxies across all specified regions,
    excluding any resources created and managed by AWS.
    
    :param session: An existing boto3 session.
    :param regions: An array of AWS regions to check.
    :return: The total count of AWS DB Proxies.
    """
    total_count = 0
    
    for region in regions:
        rds_client = session.client('rds', region_name=region)
        response = rds_client.describe_db_proxies()
        
        # Filter out AWS managed resources
        proxies = [proxy for proxy in response['DBProxies'] if not proxy['DBProxyArn'].startswith("arn:aws:rds:aws:")]
        
        total_count += len(proxies)
    
    return total_count

def aws_db_proxy_default_target_group(session, regions):
    total_count = 0
    seen_resources = set()

    for region in regions:
        rds_client = session.client('rds', region_name=region)
        
        response = rds_client.describe_db_proxy_target_groups()
        for target_group in response['DBProxyTargetGroups']:
            # Exclude resources created and managed by AWS
            if not target_group['DBProxyTargetGroupArn'].startswith('arn:aws:rds:'):
                # Use a unique identifier for the resource to prevent double counting global resources
                resource_id = target_group['DBProxyTargetGroupArn']
                if resource_id not in seen_resources:
                    seen_resources.add(resource_id)
                    total_count += 1

    return total_count

def aws_db_proxy_endpoint(session, regions):
    try:
        total_db_proxy_endpoints = 0
        global_resources = set()
        
        for region in regions:
            rds_client = session.client('rds', region_name=region)
            paginator = rds_client.get_paginator('describe_db_proxy_endpoints')
            
            response_iterator = paginator.paginate()
            for page in response_iterator:
                for proxy_endpoint in page['DBProxyEndpoints']:
                    # Exclude AWS managed resources
                    if not proxy_endpoint['DBProxyEndpointName'].startswith('aws:'):
                        resource_arn = proxy_endpoint['DBProxyEndpointArn']
                        if resource_arn not in global_resources:
                            global_resources.add(resource_arn)
                            total_db_proxy_endpoints += 1
        
        return total_db_proxy_endpoints
    
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def is_managed_by_aws(db_security_group):
    # Check for typical indicators that a DB security group is managed by AWS
    managed_tags = ['aws:', 'cloudformation', 'autogenerated']
    for tag in db_security_group.get('Tags', []):
        if any(tag['Key'].startswith(prefix) for prefix in managed_tags):
            return True
    return False

def aws_db_security_group(session, regions):
    db_security_group_count = 0
    seen_arns = set()

    for region in regions:
        rds_client = session.client('rds', region_name=region)
        paginator = rds_client.get_paginator('describe_db_security_groups')

        for page in paginator.paginate():
            for db_security_group in page['DBSecurityGroups']:
                # Exclude AWS managed DB security groups and handle global resources correctly
                if not is_managed_by_aws(db_security_group):
                    db_security_group_arn = db_security_group['DBSecurityGroupArn']
                    if db_security_group_arn not in seen_arns:
                        seen_arns.add(db_security_group_arn)
                        db_security_group_count += 1

    return db_security_group_count

def aws_db_snapshot(session, regions):
    """
    Count the total number of AWS RDS snapshots across all given regions,
    excluding resources created and managed by AWS.
    
    :param session: an existing boto3 session
    :param regions: a list of AWS regions to check
    :return: total count of user-managed RDS snapshots
    """
    total_snapshot_count = 0
    
    for region in regions:
        rds_client = session.client('rds', region_name=region)
        
        paginator = rds_client.get_paginator('describe_db_snapshots')
        page_iterator = paginator.paginate()
        
        for page in page_iterator:
            for snapshot in page['DBSnapshots']:
                # Exclude snapshots created and managed by AWS, for example automated snapshots
                if snapshot['SnapshotType'] == 'manual':
                    total_snapshot_count += 1
    
    return total_snapshot_count

def aws_db_subnet_group(session, regions):
    rds_client_global = session.client('rds')
    exclude_managed_by_aws = lambda subnet_group: not subnet_group['DBSubnetGroupName'].startswith('rdsmanaged')

    count = 0
    for region in regions:
        rds_client = session.client('rds', region_name=region)
        paginator = rds_client.get_paginator('describe_db_subnet_groups')
        for page in paginator.paginate():
            count += len(list(filter(exclude_managed_by_aws, page['DBSubnetGroups'])))
    
    # Global resources
    paginator_global = rds_client_global.get_paginator('describe_db_subnet_groups')
    for page in paginator_global.paginate():
        count += len(list(filter(exclude_managed_by_aws, page['DBSubnetGroups'])))

    return count

def aws_default_network_acl(session, regions):
    # Initialize a set to keep track of unique default ACLs
    default_acls = set()

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        
        # Describe network ACLs and retrieve only the default ones
        response = ec2_client.describe_network_acls(Filters=[
            {
                'Name': 'default',
                'Values': ['true']
            }
        ])
        
        # Iterate over the response to find ACL IDs
        for acl in response['NetworkAcls']:
            # Filter out network ACLs that are managed by AWS
            if not any(entry['RuleAction'] == 'deny' for entry in acl['Entries']):
                default_acls.add(acl['NetworkAclId'])
                
    # Return the count of unique non-aws managed default network ACLs
    return len(default_acls)

def aws_directory_service_directory(session, regions):
    def is_customer_managed(directory):
        # Placeholder function to determine if the directory is customer-managed
        return directory['Type'] == 'Customer_Managed'

    total_directories = 0
    counted_global_resources = set()
    
    for region in regions:
        ds_client = session.client('ds', region_name=region)
        paginator = ds_client.get_paginator('describe_directories')
        
        for page in paginator.paginate():
            for directory in page['DirectoryDescriptions']:
                if is_customer_managed(directory):
                    directory_id = directory['DirectoryId']
                    if directory_id not in counted_global_resources:
                        total_directories += 1
                        counted_global_resources.add(directory_id)
    
    return total_directories

def aws_docdb_cluster(session, regions):
    total_clusters = 0

    for region in regions:
        client = session.client('docdb', region_name=region)

        try:
            response = client.describe_db_clusters()
            clusters = response['DBClusters']

            for cluster in clusters:
                if not cluster.get('ManagedByAPL', False):  # Exclude resources managed by AWS
                    total_clusters += 1

        except client.exceptions.ClientError as e:
            print(f"Error querying region {region}: {e}")

    return total_clusters

def aws_docdb_cluster_instance(session, regions):
    from botocore.exceptions import NoRegionError
    

    def is_managed_by_aws(resource_name):
        # Define a helper function to check if the resource is managed by AWS.
        aws_managed_prefixes = ['aws-', 'cloudformation', 'eks', 'elasticbeanstalk']
        return any(resource_name.lower().startswith(prefix) for prefix in aws_managed_prefixes)

    def count_docdb_cluster_instances(region):
        try:
            # Create a DocDB client for the specified region
            client = session.client('docdb', region_name=region)
            paginator = client.get_paginator('describe_db_instances')
            total_count = 0

            # Paginate through the instances
            for page in paginator.paginate():
                for instance in page['DBInstances']:
                    if is_managed_by_aws(instance['DBInstanceIdentifier']):
                        continue
                    total_count += 1

            return total_count
        except NoRegionError:
            print(f"NoRegionError: Could not find region {region}")
            return 0
        except client.exceptions.ClientError as e:
            print(f"ClientError: {e}")
            return 0

    total_instances = 0
    for region in regions:
        total_instances += count_docdb_cluster_instances(region)

    return total_instances

def aws_docdb_cluster_parameter_group(session, regions):
    excluded_resources = ['default', 'aws']
    total_count = 0
    global_groups = set()

    for region in regions:
        client = session.client('docdb', region_name=region)
        paginator = client.get_paginator('describe_db_cluster_parameter_groups')
        for page in paginator.paginate():
            for param_group in page['DBClusterParameterGroups']:
                group_name = param_group['DBClusterParameterGroupName']
                if all(excluded not in group_name for excluded in excluded_resources):
                    # Assuming that parameter group names are unique across regions for global groups
                    if group_name not in global_groups:
                        global_groups.add(group_name)
                        total_count += 1

    return total_count

def aws_dynamodb_table(session, regions):
    managed_prefixes = ('aws-', 'dmscrt-', 'dax-', 'global-')
    
    # Store unique table names to handle global resources
    unique_tables = set()
    
    for region in regions:
        dynamodb_client = session.client('dynamodb', region_name=region)
        
        paginator = dynamodb_client.get_paginator('list_tables')
        for page in paginator.paginate():
            for table_name in page['TableNames']:
                if not any(table_name.startswith(prefix) for prefix in managed_prefixes):
                    unique_tables.add(table_name)
                    
    return len(unique_tables)

def aws_ebs_snapshot(session, regions):
    ec2_client = session.client('ec2')
    global_snapshot_count = 0

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        paginator = ec2_client.get_paginator('describe_snapshots')
        response_iterator = paginator.paginate(OwnerIds=['self'])

        for response in response_iterator:
            for snapshot in response['Snapshots']:
                tags = snapshot.get('Tags', [])
                if not any(tag['Key'].startswith('aws:') for tag in tags):
                    global_snapshot_count += 1

    return global_snapshot_count

def aws_ebs_volume(session, regions):
    total_volume_count = 0
    ebs_managed_tags = {
        'aws:cloudformation:stack-id',
        'aws:cloudformation:stack-name',
        'aws:cloudformation:logical-id'
    }

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        
        # Get all volumes in the region
        response = ec2_client.describe_volumes()
        volumes = response['Volumes']
        
        # Filter out managed volumes
        for volume in volumes:
            tags = volume.get('Tags', [])
            if not any(tag['Key'] in ebs_managed_tags for tag in tags):
                total_volume_count += 1
                
    return total_volume_count

def aws_ec2_traffic_mirror_filter(session, regions):
    ec2_client = session.client('ec2')
    total_mirror_filters = 0

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        response = ec2_client.describe_traffic_mirror_filters()
        
        for filter in response['TrafficMirrorFilters']:
            # Exclude resources that are created and managed by AWS
            if not filter['Description'].startswith('aws-managed'):
                total_mirror_filters += 1
    
    return total_mirror_filters

def count_traffic_mirror_sessions(session, regions):
    ec2_client = None
    total_sessions = 0

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        paginator = ec2_client.get_paginator('describe_traffic_mirror_sessions')
        for page in paginator.paginate():
            for session in page['TrafficMirrorSessions']:
                if not session['Description'].startswith('AWS managed'):
                    total_sessions += 1
    
    return total_sessions

def aws_ec2_traffic_mirror_target(session, regions):
    total_traffic_mirror_targets = 0
    seen_targets = set()  # To track global resources

    for region in regions:
        ec2 = session.client('ec2', region_name=region)
        
        paginator = ec2.get_paginator('describe_traffic_mirror_targets')
        for page in paginator.paginate():
            for target in page['TrafficMirrorTargets']:
                target_id = target['TrafficMirrorTargetId']
                if not target['NetworkInterfaceId'].startswith('eni-aws-managed'):  # Excluding AWS managed resources
                    if target_id not in seen_targets:
                        seen_targets.add(target_id)
                        total_traffic_mirror_targets += 1

    return total_traffic_mirror_targets

def aws_ec2_transit_gateway(session, regions):
    ec2_client = session.client('ec2')
    total_transit_gateways = 0

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        response = ec2_client.describe_transit_gateways()
        
        for tg in response['TransitGateways']:
            # Skip resources created and managed by AWS
            if tg['OwnerId'] != 'amazon':
                total_transit_gateways += 1

    return total_transit_gateways

def aws_ec2_transit_gateway_peering_attachment(session, regions):
    total_count = 0
    seen_attachments = set()

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        
        # Describe transit gateway peering attachments
        response = ec2_client.describe_transit_gateway_peering_attachments(Filters=[
            {
                'Name': 'state',
                'Values': ['available']
            }
        ])
        
        for attachment in response['TransitGatewayPeeringAttachments']:
            attachment_id = attachment['TransitGatewayAttachmentId']
            
            # Assume that AWS managed resources have a specific pattern, e.g., "aws-"
            if not attachment_id.startswith("aws-") and attachment_id not in seen_attachments:
                seen_attachments.add(attachment_id)
                total_count += 1
                
    return total_count

def aws_ec2_transit_gateway_peering_attachment_accepter(session, regions):
    ec2_client = session.client("ec2")
    total_count = 0
    counted_global_resources = set()

    for region in regions:
        regional_client = session.client("ec2", region_name=region)
        paginator = regional_client.get_paginator('describe_transit_gateway_peering_attachments')
        global_filter = {'Name': 'is-global-resource', 'Values': ['true']}
        
        for page in paginator.paginate(Filters=[global_filter]):
            for attachment in page['TransitGatewayPeeringAttachments']:
                if attachment['TransitGatewayPeeringAttachmentId'] not in counted_global_resources and \
                   not attachment['TransitGatewayPeeringAttachmentId'].startswith('aws-'):
                    counted_global_resources.add(attachment['TransitGatewayPeeringAttachmentId'])
        
        for page in paginator.paginate():
            for attachment in page['TransitGatewayPeeringAttachments']:
                if not attachment['TransitGatewayPeeringAttachmentId'].startswith('aws-'):
                    total_count += 1

    total_count -= len(counted_global_resources)
    return total_count

def aws_ec2_transit_gateway_route(session, regions):
    

    def count_routes_in_region(region):
        ec2 = session.client('ec2', region_name=region)
        response = ec2.describe_transit_gateway_routes(
            Filters=[
                {
                    'Name': 'state',
                    'Values': ['active', 'blackhole']
                }
            ]
        )
        
        # Filter out routes managed by AWS
        custom_routes = [route for route in response['TransitGatewayRoutes'] if not route.get('Type') == 'propagated']
        return len(custom_routes)

    total_route_count = 0
    for region in regions:
        total_route_count += count_routes_in_region(region)
    
    return total_route_count

def aws_ec2_transit_gateway_route_table(session, regions):
    

    # Initialize a counter for the total number of transit gateway route tables
    total_route_tables = 0

    # Iterate over each region
    for region in regions:
        # Create an EC2 client for the current region
        ec2_client = session.client('ec2', region_name=region)
        
        # Get a list of all transit gateway route tables
        try:
            response = ec2_client.describe_transit_gateway_route_tables()
            for route_table in response['TransitGatewayRouteTables']:
                # Exclude any resources created and managed by AWS (could use tags or other identifying info)
                if not route_table.get('Tags') or not any(tag['Key'] == 'aws:createdBy' and tag['Value'] == 'AWS' for tag in route_table['Tags']):
                    total_route_tables += 1
        except Exception as e:
            print(f"Error describing transit gateway route tables in region {region}: {e}")

    return total_route_tables

def aws_ec2_transit_gateway_route_table_propagation(session, regions):
    def is_managed_by_aws(propagation):
        # Assuming 'ResourceId' or some similar identifier can be used to identify AWS managed resources
        resource_id = propagation.get('ResourceId', '')
        # Adjust the condition appropriately based on specific characteristics of AWS-managed resources.
        return resource_id.startswith('aws-')

    total_propagations = set()

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)

        try:
            tgw_route_tables = ec2_client.describe_transit_gateway_route_tables()['TransitGatewayRouteTables']
            for tgw_route_table in tgw_route_tables:
                propagations = ec2_client.get_transit_gateway_route_table_propagations(
                    TransitGatewayRouteTableId=tgw_route_table['TransitGatewayRouteTableId']
                )['TransitGatewayRouteTablePropagations']

                for propagation in propagations:
                    if is_managed_by_aws(propagation):
                        continue
                    # Use a combination of region and RouteTableId as a composite key to ensure global uniqueness
                    total_propagations.add(f"{region}:{propagation['TransitGatewayAttachmentId']}")
        except Exception as e:
            print(f"An error occurred in region {region}: {e}")

    return len(total_propagations)

def aws_ec2_transit_gateway_vpc_attachment(session, regions):
    

    total_attachments = 0
    aws_managed_patterns = ['aws', 'amazon', 'elasticache']

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        response = ec2_client.describe_transit_gateway_vpc_attachments()
        
        for attachment in response['TransitGatewayVpcAttachments']:
            if not any(pattern in attachment.get('Description', '').lower() for pattern in aws_managed_patterns):
                total_attachments += 1
                
    return total_attachments

def aws_ec2_transit_gateway_vpc_attachment_accepter(session, regions):
    """
    Function to count the total number of AWS EC2 Transit Gateway VPC Attachment Accepters across 
    all specified regions, excluding resources created and managed by AWS.

    :param session: Boto3 session object
    :param regions: List of AWS regions to check
    :return: Total count of Transit Gateway VPC Attachment Accepters
    """

    total_count = 0
    
    for region in regions:
        # Create EC2 client for the specified region
        ec2_client = session.client('ec2', region_name=region)
        
        # Retrieve the list of Transit Gateway VPC Attachment Accepters
        response = ec2_client.describe_transit_gateway_vpc_attachments()
        attachments = response.get('TransitGatewayVpcAttachments', [])
        
        for attachment in attachments:
            # Ensure we exclude AWS-managed resources
            if 'aws:' not in attachment.get('Tags', []):
                total_count += 1
    
    return total_count

def aws_ecr_lifecycle_policy(session, regions):
    
    

    count = 0

    for region in regions:
        ecr_client = session.client('ecr', region_name=region)
        try:
            repositories = ecr_client.describe_repositories()['repositories']
            for repo in repositories:
                policy_response = ecr_client.get_lifecycle_policy(repositoryName=repo['repositoryName'])
                if 'lifecyclePolicyText' in policy_response:
                    count += 1
        except ClientError as error:
            # handle known exceptions or just pass to ignore errors
            print(f"Skipping region {region} due to error: {error}")
            pass

    return count

def aws_ecr_replication_configuration(session, regions):
    total_count = 0
    unique_repos = set()

    for region in regions:
        ecr_client = session.client('ecr', region_name=region)
        paginator = ecr_client.get_paginator('describe_repositories')
        page_iterator = paginator.paginate()

        for page in page_iterator:
            for repo in page['repositories']:
                repo_name = repo['repositoryName']
                if not repo['repositoryArn'].startswith('arn:aws:ecr:replication:'):
                    unique_repos.add(repo_name)

    total_count = len(unique_repos)
    return total_count

def aws_ecr_repository(session, regions):
    

    def is_managed_by_aws(repo_name):
        # You can adjust/add more rules to identify AWS managed resources
        aws_managed_prefixes = ['aws']
        return any(repo_name.startswith(prefix) for prefix in aws_managed_prefixes)

    total_repos = 0
    checked_arns = set()  # To ensure global resources are only counted once

    for region in regions:
        ecr_client = session.client('ecr', region_name=region)
        paginator = ecr_client.get_paginator('describe_repositories')
        
        for page in paginator.paginate():
            for repo in page['repositories']:
                repo_name = repo['repositoryName']
                repo_arn = repo['repositoryArn']
                
                if not is_managed_by_aws(repo_name) and repo_arn not in checked_arns:
                    checked_arns.add(repo_arn)
                    total_repos += 1

    return total_repos

def aws_ecr_repository_policy(session, regions):
    total_policies = 0
    ecr_resources_set = set()  # To track unique repositories

    for region in regions:
        ecr_client = session.client('ecr', region_name=region)
        
        try:
            response = ecr_client.describe_repositories()
            repositories = response['repositories']
            
            while 'nextToken' in response:
                response = ecr_client.describe_repositories(nextToken=response['nextToken'])
                repositories.extend(response['repositories'])
            
            for repo in repositories:
                # Skip AWS managed resources
                if not repo['repositoryArn'].startswith('arn:aws:ecr:') or repo['repositoryName'].startswith('aws'):
                    continue

                # Add unique repository ARNs to the set to avoid double counting
                ecr_resources_set.add(repo['repositoryArn'])
        
        except ecr_client.exceptions.ClientError as error:
            print(f"An error occurred in region {region}: {error}")
            continue

    total_policies = len(ecr_resources_set)
    return total_policies

def aws_ecrpublic_repository(session, regions):
    
    
    total_repositories = 0
    ecrpublic_dashboards = set()  # To ensure global resources (if any) are counted only once
    
    for region in regions:
        # Create a client for ECR Public in the given region
        ecrpublic_client = session.client('ecr-public', region_name=region)
        
        # Paginate through all repositories
        paginator = ecrpublic_client.get_paginator('describe_repositories')
        for page in paginator.paginate():
            for repository in page.get('repositories', []):
                repo_name = repository['repositoryName']
                # Exclude any repositories managed by AWS (Assuming a condition for this)
                if not repo_name.startswith('aws'):
                    ecrpublic_dashboards.add(repo_name)
    
    total_repositories = len(ecrpublic_dashboards)
    
    return total_repositories

# def aws_ecs_capacity_provider(session, regions):
#     ecs_capacity_provider_count = 0
#     seen_capacity_providers = set()
    
#     for region in regions:
#         ecs_client = session.client('ecs', region_name=region)
        
#         paginator = ecs_client.get_paginator('describe_capacity_providers')
#         page_iterator = paginator.paginate()
        
#         for page in page_iterator:
#             for capacity_provider in page['capacityProviders']:
#                 cp_name = capacity_provider['capacityProviderArn']
                
#                 if cp_name not in seen_capacity_providers and not cp_name.startswith("arn:aws:ecs:") and not cp_name.endswith(":AWSServiceRoleForAutoScaling"):
#                     seen_capacity_providers.add(cp_name)
#                     ecs_capacity_provider_count += 1
    
#     return ecs_capacity_provider_count

def aws_ecs_capacity_provider(session, regions):
    ecs_capacity_provider_count = 0
    seen_capacity_providers = set()
    
    for region in regions:
        ecs_client = session.client('ecs', region_name=region)
        
        # List capacity providers using describe_capacity_providers
        try:
            response = ecs_client.describe_capacity_providers()
            for cp in response['capacityProviders']:
                cp_name = cp['name']
                if cp_name not in seen_capacity_providers:
                    seen_capacity_providers.add(cp_name)
                    ecs_capacity_provider_count += 1
        except Exception as e:
            print(f"Error fetching capacity providers for region {region}: {str(e)}")
    
    return ecs_capacity_provider_count

def aws_ecs_cluster(session, regions):
    total_clusters = 0
    seen_clusters = set()  # To ensure we only count global clusters once

    for region in regions:
        ecs_client = session.client('ecs', region_name=region)
        
        paginator = ecs_client.get_paginator('list_clusters')
        for page in paginator.paginate():
            for cluster_arn in page['clusterArns']:
                cluster_name = cluster_arn.split('/')[-1]
                
                if cluster_name.startswith('aws:'):  # Skip AWS managed clusters
                    continue
                
                # Check if the cluster is global (present in seen_clusters)
                if cluster_name not in seen_clusters:
                    seen_clusters.add(cluster_name)
                    total_clusters += 1

    return total_clusters

def aws_ecs_service(session, regions):
    
    def is_managed_by_aws(resource_arn):
        aws_managed_prefixes = [
            'aws:',
            'arn:aws:resource-groups:',
            'arn:aws:ssm:',
            'arn:aws:cloudformation:'
        ]
        return any(resource_arn.startswith(prefix) for prefix in aws_managed_prefixes)
    
    total_service_count = 0
    checked_resources = set()  # To keep track of globally unique resources
    for region in regions:
        ecs_client = session.client('ecs', region_name=region)
        # Paginate through list_services calls
        paginator = ecs_client.get_paginator('list_services')
        page_iterator = paginator.paginate()
        for page in page_iterator:
            for service_arn in page['serviceArns']:
                if service_arn not in checked_resources and not is_managed_by_aws(service_arn):
                    checked_resources.add(service_arn)
                    total_service_count += 1
    
    return total_service_count

def aws_ecs_task_definition(session, regions):
    ecs_client = session.client('ecs', region_name=regions[0])
    
    # Deduplicated task definition ARNs to account for global resources
    global_task_definitions = set()

    for region in regions:
        ecs_client = session.client('ecs', region_name=region)
        
        # Using pagination to ensure all task definitions are retrieved
        paginator = ecs_client.get_paginator('list_task_definitions')
        for page in paginator.paginate(status='ACTIVE'):
            for task_definition_arn in page['taskDefinitionArns']:
                task_definition_name = task_definition_arn.split('/')[-1].split(':')[0]
                
                # Exclude AWS managed task definitions
                if not task_definition_name.startswith('aws-'):
                    global_task_definitions.add(task_definition_arn)
    
    return len(global_task_definitions)

def aws_efs_access_point(session, regions):
    
    

    total_access_points = 0

    for region in regions:
        # Create an EFS client for the region
        efs_client = session.client('efs', region_name=region)
        
        try:
            # List all access points in the region
            response = efs_client.describe_access_points()
            access_points = response.get('AccessPoints', [])

            # Filter out any access points that are created and managed by AWS
            user_managed_access_points = [
                ap for ap in access_points 
                if not ap['Name'].startswith('aws-managed')
            ]
            
            total_access_points += len(user_managed_access_points)

        except ClientError as e:
            print(f"Error fetching access points in region {region}: {e}")

    return total_access_points

def aws_efs_file_system(session, regions):
    

    total_file_systems = 0

    for region in regions:
        efs_client = session.client('efs', region_name=region)
        response = efs_client.describe_file_systems()

        for fs in response['FileSystems']:
            tags_response = efs_client.describe_tags(FileSystemId=fs['FileSystemId'])
            aws_managed = False
            for tag in tags_response['Tags']:
                if tag['Key'].startswith('aws:'):
                    aws_managed = True
                    break
            if not aws_managed:
                total_file_systems += 1

    return total_file_systems

def aws_eip(session, regions):
    """
    Count the total number of Elastic IPs (EIPs) across all specified regions,
    excluding those created and managed by AWS. Global resources are counted once.

    :param session: Existing boto3 session.
    :param regions: List of AWS regions to check.
    :return: Total count of non-AWS-managed EIPs across the specified regions.
    """
    unique_eips = set()

    def is_aws_managed_eip(eip):
        """Check if the Elastic IP is managed by AWS"""
        tags = eip.get('Tags', [])
        for tag in tags:
            if tag['Key'] == 'aws:cloudformation:stack-name':
                return True
        return False

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        
        response = ec2_client.describe_addresses()
        for address in response['Addresses']:
            if not is_aws_managed_eip(address):
                unique_eips.add(address['PublicIp'])

    # Return the number of unique Elastic IPs across all regions
    return len(unique_eips)

def aws_eks_addon(session, regions):
    eks_addon_count = 0
    aws_managed_addons = {
        'vpc-cni',   # Example: AWS CNI plugin
        'core-dns',  # Example: CoreDNS
        'kube-proxy' # Example: Kube-proxy
    }

    for region in regions:
        eks_client = session.client('eks', region_name=region)
        try:
            clusters = eks_client.list_clusters()
            for cluster in clusters['clusters']:
                addons = eks_client.list_addons(clusterName=cluster)
                eks_addon_count += len(
                    set(addons['addons']) - aws_managed_addons
                )
        except eks_client.exceptions.ClientError as e:
            print(f"An error occurred: {e}")
    
    return eks_addon_count

def aws_eks_cluster(session, regions):
    eks_clusters_count = 0
    aws_managed_keys = ['eksManaged']

    for region in regions:
        eks_client = session.client('eks', region_name=region)
        clusters_response = eks_client.list_clusters()
        
        for cluster_name in clusters_response['clusters']:
            cluster_info = eks_client.describe_cluster(name=cluster_name)
            if not any(key in cluster_info['cluster']['tags'] for key in aws_managed_keys):
                eks_clusters_count += 1
    
    return eks_clusters_count

# def aws_eks_fargate_profile(session, regions):
    
    
#     def is_aws_resource(fargate_profile):
#         '''Checks if the Fargate profile is managed by AWS'''
#         # Example checking criteria: AWS managed resources might have "AWSControlPlane" in their Arn
#         return 'AWSControlPlane' in fargate_profile.get('fargateProfileName', '')
    
#     def get_fargate_profiles_count(eks_client):
#         '''Get count of Fargate profiles not managed by AWS'''
#         count = 0
#         paginator = eks_client.get_paginator('list_fargate_profiles')
#         for page in paginator.paginate():
#             for profile in page['fargateProfileNames']:
#                 profile_info = eks_client.describe_fargate_profile(
#                     clusterName=profile.split(':')[0],
#                     fargateProfileName=profile
#                 )['fargateProfile']
#                 if not is_aws_resource(profile_info):
#                     count += 1
#         return count

#     total_count = 0
#     for region in regions:
#         eks_client = session.client('eks', region_name=region)
#         total_count += get_fargate_profiles_count(eks_client)
    
#     return total_count

def aws_eks_fargate_profile(session, regions):
    
    def is_aws_resource(fargate_profile):
        '''Checks if the Fargate profile is managed by AWS'''
        # Example checking criteria: AWS managed resources might have "AWSControlPlane" in their Arn
        return 'AWSControlPlane' in fargate_profile.get('fargateProfileName', '')
    
    def get_fargate_profiles_count(eks_client, cluster_name):
        '''Get count of Fargate profiles not managed by AWS'''
        count = 0
        paginator = eks_client.get_paginator('list_fargate_profiles')
        for page in paginator.paginate(clusterName=cluster_name):
            for profile_name in page['fargateProfileNames']:
                profile_info = eks_client.describe_fargate_profile(
                    clusterName=cluster_name,
                    fargateProfileName=profile_name
                )['fargateProfile']
                if not is_aws_resource(profile_info):
                    count += 1
        return count

    total_count = 0
    for region in regions:
        eks_client = session.client('eks', region_name=region)
        clusters_response = eks_client.list_clusters()
        for cluster_name in clusters_response['clusters']:
            total_count += get_fargate_profiles_count(eks_client, cluster_name)
    
    return total_count

def aws_eks_identity_provider_config(session, regions):
    total_count = 0
    seen_configs = set()

    for region in regions:
        eks_client = session.client('eks', region_name=region)
        paginator = eks_client.get_paginator('list_identity_provider_configs')
        
        try:
            for page in paginator.paginate():
                for config in page['identityProviderConfigs']:
                    config_name = config['name']
                    config_type = config['type']
                    
                    # Use a combination of name and type to identify unique configs
                    config_key = f"{config_name}:{config_type}"
                    
                    if config_key not in seen_configs and 'aws' not in config_name.lower():
                        seen_configs.add(config_key)
                        total_count += 1
        except eks_client.exceptions.ClientError as error:
            print(f"An error occurred: {error}")
            continue

    return total_count

def aws_eks_node_group(session, regions):
    eks_client = session.client('eks')
    total_node_groups = 0

    for region in regions:
        eks_client = session.client('eks', region_name=region)
        
        clusters = eks_client.list_clusters()['clusters']
        for cluster in clusters:
            node_groups = eks_client.list_nodegroups(clusterName=cluster)['nodegroups']
            
            for node_group in node_groups:
                node_group_details = eks_client.describe_nodegroup(clusterName=cluster, nodegroupName=node_group)
                
                # Exclude node groups managed by AWS
                if not node_group_details['nodegroup']['labels'].get('eks.amazonaws.com/nodegroup'):
                    total_node_groups += 1

    return total_node_groups

def aws_elastic_beanstalk_application(session, regions):
    app_count = 0
    
    for region in regions:
        eb_client = session.client('elasticbeanstalk', region_name=region)
        
        # Paginate through all applications in the region
        paginator = eb_client.get_paginator('describe_applications')
        page_iterator = paginator.paginate()
        
        for page in page_iterator:
            for app in page['Applications']:
                app_name = app['ApplicationName']
                
                # Exclude AWS managed resources
                if not app_name.startswith('aws-'):
                    app_count += 1

    return app_count

def aws_elastic_beanstalk_environment(session, regions):
    

    total_environments = 0

    for region in regions:
        eb_client = session.client('elasticbeanstalk', region_name=region)
        response = eb_client.describe_environments()

        # Filter out environments managed by AWS
        user_managed_environments = [env for env in response['Environments'] 
                                     if not env['EnvironmentName'].startswith('aws-managed-')]
        
        total_environments += len(user_managed_environments)
        
    return total_environments

def aws_elasticache_cluster(session, regions):
    total_cluster_count = 0
    unique_resources = set()

    for region in regions:
        elasticache_client = session.client('elasticache', region_name=region)
        paginator = elasticache_client.get_paginator('describe_cache_clusters')
        for page in paginator.paginate():
            for cluster in page['CacheClusters']:
                if 'aws:' not in cluster['CacheClusterId']:
                    unique_resources.add(cluster['CacheClusterId'])

    total_cluster_count = len(unique_resources)
    return total_cluster_count

def aws_elasticache_parameter_group(session, regions):
    """
    Count the total number of ElastiCache parameter groups across all specified regions.
    Exclude any resources that are created and managed by AWS. 
    Ensure that global resources are only counted once.

    :param session: Boto3 session object
    :param regions: List of AWS regions
    :return: Total count of ElastiCache parameter groups excluding AWS managed resources
    """
    total_count = set()

    for region in regions:
        client = session.client('elasticache', region_name=region)
        paginator = client.get_paginator('describe_cache_parameter_groups')
        
        for page in paginator.paginate():
            for parameter_group in page['CacheParameterGroups']:
                if not parameter_group['CacheParameterGroupName'].startswith('default'):
                    total_count.add(parameter_group['CacheParameterGroupName'])
    
    return len(total_count)

def aws_elasticache_replication_group(session, regions):
    """
    Count the total number of AWS ElastiCache replication groups across all given regions, excluding AWS-managed resources.
    
    Parameters:
    session (boto3.Session): An existing boto3 session.
    regions (list): Array of AWS regions.
    
    Returns:
    int: The total count of AWS ElastiCache replication groups, excluding AWS-managed resources.
    """
    
    
    def is_custom_resource(replication_group):
        """Check if the replication group is custom-managed, not AWS-managed."""
        aws_managed_identifiers = ['aws', 'amazon']
        for identifier in aws_managed_identifiers:
            if identifier in replication_group['ReplicationGroupId'].lower():
                return False
        return True

    total_count = 0

    for region in regions:
        client = session.client('elasticache', region_name=region)
        paginator = client.get_paginator('describe_replication_groups')
        page_iterator = paginator.paginate()

        for page in page_iterator:
            custom_resources = filter(is_custom_resource, page['ReplicationGroups'])
            total_count += len(list(custom_resources))

    return total_count

def aws_elasticache_subnet_group(session, regions):
    count = 0
    unique_subnet_groups = set()

    for region in regions:
        client = session.client('elasticache', region_name=region)
        paginator = client.get_paginator('describe_cache_subnet_groups')
        
        for page in paginator.paginate():
            for subnet_group in page['CacheSubnetGroups']:
                if not subnet_group['CacheSubnetGroupName'].startswith('aws-'):
                    unique_subnet_groups.add(subnet_group['CacheSubnetGroupName'])
    
    count = len(unique_subnet_groups)
    return count

def aws_elasticache_user(session, regions):
    

    # Initialize a counter to keep track of total users
    total_user_count = 0

    # Loop through each region and count the AWS Elasticache users
    for region in regions:
        # Create a new client for the elasticache service in the given region
        elasticache_client = session.client('elasticache', region_name=region)
        
        # Use a paginator to handle the case where there are many users
        paginator = elasticache_client.get_paginator('describe_users')
        page_iterator = paginator.paginate()
        
        # Iterate through each page of results
        for page in page_iterator:
            users = page["Users"]
            for user in users:
                # Exclude AWS managed resources by checking the "UserGroupId"
                if not user['UserId'].startswith("aws-"):
                    total_user_count += 1

    return total_user_count

def aws_elasticache_user_group(session, regions):
    user_group_count = 0
    global_user_group_set = set()
    
    for region in regions:
        try:
            elasticache_client = session.client('elasticache', region_name=region)
            paginator = elasticache_client.get_paginator('describe_user_groups')
            for page in paginator.paginate():
                for user_group in page.get('UserGroups', []):
                    user_group_id = user_group.get('UserGroupId')
                    if user_group_id and not user_group_id.startswith('aws:'):
                        # Check if this is a global resource based on UserGroupId.
                        if user_group.get('Engine', '').lower() == 'global': 
                            global_user_group_set.add(user_group_id)
                        else:
                            user_group_count += 1
        except Exception as e:
            print(f"Error in region {region}: {e}")

    # Total user groups will be non-global user groups plus unique global user groups
    user_group_count += len(global_user_group_set)
    
    return user_group_count

def aws_elasticsearch_domain(session, regions):
    es_domains_count = set()

    for region in regions:
        es_client = session.client('es', region_name=region)
        try:
            response = es_client.list_domain_names()
            for domain_info in response['DomainNames']:
                domain_name = domain_info['DomainName']
                domain_data = es_client.describe_elasticsearch_domain(DomainName=domain_name)
                es_domain = domain_data['DomainStatus']
                
                # Exclude AWS managed domains
                if not es_domain.get('CreatedBy', {}).get('Type') == 'AWSService':
                    es_domains_count.add(domain_name)
        except Exception as e:
            print(f"Error fetching details in {region}: {e}")

    return len(es_domains_count)

def aws_emr_cluster(session, regions):
    total_clusters_count = 0
    managed_by_aws_prefix = ['AWS-', 'aws-', 'Managed-']
    
    for region in regions:
        emr_client = session.client('emr', region_name=region)
        paginator = emr_client.get_paginator('list_clusters')
        cluster_iterator = paginator.paginate()

        for page in cluster_iterator:
            clusters = page['Clusters']
            for cluster in clusters:
                if not any(cluster['Name'].startswith(prefix) for prefix in managed_by_aws_prefix):
                    total_clusters_count += 1
    return total_clusters_count

def aws_flow_log(session, regions):
    client = session.client('ec2')
    total_count = 0
    global_resource_ids = set()

    for region in regions:
        regional_client = session.client('ec2', region_name=region)
        paginator = regional_client.get_paginator('describe_flow_logs')
        
        for page in paginator.paginate(Filters=[{'Name': 'log-destination-type', 'Values': ['cloud-watch-logs', 's3']}]):
            for flow_log in page['FlowLogs']:
                if 'Tags' in flow_log:
                    if any(tag['Key'] == 'aws:createdBy' for tag in flow_log['Tags']):
                        continue  # Skip AWS-managed resources
                
                # Consider global resources only once
                if flow_log['FlowLogId'] not in global_resource_ids:
                    global_resource_ids.add(flow_log['FlowLogId'])
                    total_count += 1
    
    print(f'Total number of VPC Flow Logs (excluding AWS-managed): {total_count}')
    return total_count

def aws_globalaccelerator_accelerator(session, regions):
    
    from botocore.exceptions import NoRegionError

    def is_managed_by_aws(tags):
        """
        Check if the accelerator is created and managed by AWS based on its tags.
        """
        for tag in tags:
            if tag['Key'].startswith('aws:'):
                return True
        return False

    def get_unique_accelerators():
        """
        Get a set of unique accelerator ARNs across all regions.
        """
        unique_accelerators = set()
        for region in regions:
            try:
                ga_client = session.client('globalaccelerator', region_name=region)
                paginator = ga_client.get_paginator('list_accelerators')
                for page in paginator.paginate():
                    for accelerator in page.get('Accelerators', []):
                        if not accelerator['Enabled']:
                            continue
                        arn = accelerator['AcceleratorArn']
                        tags = ga_client.list_tags_for_resource(ResourceArn=arn).get('Tags', [])
                        if not is_managed_by_aws(tags):
                            unique_accelerators.add(arn)
            except NoRegionError:
                print(f"Region {region} does not support Global Accelerator.")
            except Exception as e:
                print(f"An error occurred in region {region}: {e}")
        return unique_accelerators

    unique_accelerators = get_unique_accelerators()
    return len(unique_accelerators)

def aws_globalaccelerator_listener(session, regions):
    client_globalaccelerator = session.client('globalaccelerator')
    total_listener_count = 0

    # A global resource is typically counted only once, we'll use a flag for that
    # Since Global Accelerator is a global resource, we query the service in just one region.
    global_query_region = regions[0]
    
    client_globalaccelerator = session.client('globalaccelerator', region_name=global_query_region)
    
    try:
        accelerators = client_globalaccelerator.list_accelerators()
        for accelerator in accelerators['Accelerators']:
            if accelerator['Enabled']:
                arn = accelerator['AcceleratorArn']
                listeners = client_globalaccelerator.list_listeners(AcceleratorArn=arn)
                for listener in listeners['Listeners']:
                    if not 'aws:' in listener['ListenerArn']:
                        total_listener_count += 1
    
    except Exception as e:
        print(f"Error fetching global accelerators: {e}")

    return total_listener_count

def aws_glue_catalog_database(session, regions):
    def is_not_aws_managed(database_name):
        aws_managed_prefixes = ["aws_", "Amazon", "aws-glue", "cloudtrail"]
        for prefix in aws_managed_prefixes:
            if database_name.lower().startswith(prefix.lower()):
                return False
        return True

    glue_client = session.client('glue')
    total_databases = set()
    for region in regions:
        glue_client = session.client('glue', region_name=region)
        paginator = glue_client.get_paginator('get_databases')
        iterator = paginator.paginate()
        for page in iterator:
            for db in page['DatabaseList']:
                db_name = db['Name']
                if is_not_aws_managed(db_name):
                    total_databases.add(db_name)
    
    return len(total_databases)

def aws_glue_catalog_table(session, regions):
    """
    Counts the total number of AWS Glue catalog tables across all specified AWS regions.
    Excludes resources created and managed by AWS.

    Parameters:
    session (boto3.Session): An existing boto3 session
    regions (list of str): List of AWS regions to check for Glue catalog tables

    Returns:
    int: Total count of user-managed Glue catalog tables
    """
    glue_client = session.client('glue')
    total_table_count = 0

    for region in regions:
        # Create a regional Glue client
        regional_glue_client = session.client('glue', region_name=region)
        
        paginator = regional_glue_client.get_paginator('get_databases')
        for page in paginator.paginate():
            for database in page['DatabaseList']:
                database_name = database['Name']

                table_paginator = regional_glue_client.get_paginator('get_tables')
                for tables_page in table_paginator.paginate(DatabaseName=database_name):
                    for table in tables_page['TableList']:
                        # Exclude AWS managed tables
                        if not table['Name'].startswith('Aws'):
                            total_table_count += 1

    return total_table_count

def aws_glue_crawler(session, regions):
    total_crawlers = 0
    aws_managed_prefix = 'aws-'

    for region in regions:
        glue_client = session.client('glue', region_name=region)
        paginator = glue_client.get_paginator('get_crawlers')
        
        for page in paginator.paginate():
            crawlers = page['Crawlers']
            user_managed_crawlers = [crawler for crawler in crawlers if not crawler['Name'].startswith(aws_managed_prefix)]
            total_crawlers += len(user_managed_crawlers)
    
    return total_crawlers

def aws_glue_resource_policy(session, regions):
    # Function to check if the resource policy is created and managed by AWS
    def is_managed_by_aws(resource_policy):
        for statement in resource_policy.get('PolicyInJson', {}).get('Statement', []):
            if statement.get('Principal') == '*':
                return True
        return False

    resource_policy_count = 0
    counted_resources = set()

    for region in regions:
        glue_client = session.client('glue', region_name=region)

        try:
            response = glue_client.get_resource_policies()
        except glue_client.exceptions.InvalidInputException:
            # Handle situations where the API call fails in a region, e.g., if the Glue service is not available
            continue

        for policy in response.get('GetResourcePoliciesResponse', []):
            resource_id = policy.get('ResourceArn')
            if resource_id not in counted_resources and not is_managed_by_aws(policy):
                counted_resources.add(resource_id)
                resource_policy_count += 1

    return resource_policy_count

def aws_iam_group(session, regions):
    try:
        iam_client = session.client('iam')
        paginator = iam_client.get_paginator('list_groups')
        
        group_names = set()  # use a set to ensure unique group names

        for page in paginator.paginate():
            for group in page['Groups']:
                group_names.add(group['GroupName'])

        total_groups = len(group_names)

        return total_groups
    
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

def aws_iam_instance_profile(session, regions):
    # Create an IAM client using the session
    iam_client = session.client('iam')
    
    # Get a list of all instance profiles
    instance_profiles = iam_client.list_instance_profiles()
    
    # Filter out instance profiles that are created and managed by AWS
    custom_instance_profiles = [ip for ip in instance_profiles['InstanceProfiles'] if not ip['Path'].startswith('/aws-service-role/')]
    
    # Initialize total count of instance profiles
    total_count = len(custom_instance_profiles)
    
    return total_count

def aws_iam_openid_connect_provider(session, regions):
    
    

    def is_managed_by_aws(provider_arn):
        """Check if the OpenID Connect provider is managed by AWS."""
        aws_managed_prefix = 'arn:aws:iam::aws:oidc-provider/'
        return provider_arn.startswith(aws_managed_prefix)

    # Initialize counts
    total_openid_connect_providers = set()

    # Loop through each region and count OpenID Connect providers
    for region in regions:
        try:
            iam_client = session.client('iam', region_name=region)
            response = iam_client.list_open_id_connect_providers()

            for provider in response['OpenIDConnectProviderList']:
                provider_arn = provider['Arn']
                if not is_managed_by_aws(provider_arn):
                    total_openid_connect_providers.add(provider_arn)
        except ClientError as error:
            # Handle error gracefully if a region is not available or any other errors
            print(f"An error occurred in region {region}: {error}")

    # Return the total count of unique OpenID Connect providers
    return len(total_openid_connect_providers)

def aws_iam_policy(session, regions):
    iam_client = session.client('iam')
    count = 0

    # Get all the managed policies
    paginator = iam_client.get_paginator('list_policies')
    for page in paginator.paginate(Scope='All'):
        for policy in page['Policies']:
            # Exclude AWS managed policies
            if not policy['Arn'].startswith('arn:aws:iam::aws:policy'):
                count += 1
    
    return count

def aws_iam_role(session, regions):
    
    
    iam_client = session.client('iam')
    
    # Fetch all IAM roles
    roles = iam_client.list_roles()
    
    # Exclude AWS managed roles
    user_roles = [role for role in roles['Roles'] if not role['Arn'].startswith('arn:aws:iam::aws:role/')]
    
    # Return the total count
    return len(user_roles)

def aws_iam_user(session, regions):
    iam = session.client('iam')
    paginator = iam.get_paginator('list_users')
    
    aws_managed_prefixes = ['aws-']
    
    total_user_count = 0
    
    for page in paginator.paginate():
        users = page['Users']
        
        for user in users:
            user_name = user['UserName']
            
            if not any(user_name.startswith(prefix) for prefix in aws_managed_prefixes):
                total_user_count += 1
                
    return total_user_count

def aws_iam_virtual_mfa_device(session, regions):
    """
    Count the total number of IAM virtual MFA devices across all specified regions,
    excluding resources created and managed by AWS. Global resources are counted only once.
    
    Args:
    session (boto3.Session): An existing Boto3 session.
    regions (list of str): An array of AWS regions.
    
    Returns:
    int: Total number of IAM virtual MFA devices.
    """
    iam_client = session.client('iam')
    
    # Create a set to track globally unique MFA devices
    counted_mfa_devices = set()
    
    # Get the list of MFA devices (global resource)
    paginator = iam_client.get_paginator('list_virtual_mfa_devices')
    
    for page in paginator.paginate():
        for mfa_device in page['VirtualMFADevices']:
            # Exclude any AWS managed or created resources
            if 'AWS' not in mfa_device['SerialNumber']:
                counted_mfa_devices.add(mfa_device['SerialNumber'])
    
    # Return the total count of unique MFA devices
    return len(counted_mfa_devices)

def aws_instance(session, regions):
    """
    Count the total number of EC2 instances across all specified regions,
    excluding those created and managed by AWS. Global resources are counted once.

    :param session: Existing boto3 session.
    :param regions: List of AWS regions to check.
    :return: Total count of non-AWS-managed EC2 instances across the specified regions.
    """
    unique_instances = set()

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        
        paginator = ec2_client.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    unique_instances.add(instance['InstanceId'])

    # Return the number of unique EC2 instances across all regions
    return len(unique_instances)

def aws_instance_total(session, regions):

    global_resources = set()

    def count_instances(ec2_client):
        paginator = ec2_client.get_paginator('describe_instances')
        page_iterator = paginator.paginate()
        instance_count = 0
        for page in page_iterator:
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    if not instance['Tags'] or not any(tag['Key'].startswith('aws:') for tag in instance['Tags']):
                        instance_count += 1
        return instance_count

    total_instances = 0
    
    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        total_instances += count_instances(ec2_client)

        # Assuming resource IDs for global resources start with 'global-' prefix (modify this as needed)
        for resource in ec2_client.describe_instances()['Reservations']:
            for instance in resource['Instances']:
                if instance['InstanceId'].startswith('global-') and instance['InstanceId'] not in global_resources:
                    global_resources.add(instance['InstanceId'])

    total_count = total_instances + len(global_resources)
    return total_count

def aws_internet_gateway(session, regions):
    ec2_client = {}
    igw_count = 0

    # Loop through each region
    for region in regions:
        ec2_client[region] = session.client('ec2', region_name=region)
        
        # Describe all internet gateways in the region
        response = ec2_client[region].describe_internet_gateways()
        
        # Filter internet gateways that are not managed by AWS
        for igw in response['InternetGateways']:
            if 'Tags' in igw:
                for tag in igw['Tags']:
                    if tag['Key'].startswith('aws:') and tag['Value'].startswith('managed'):
                        break
                else:
                    igw_count += 1
            else:
                igw_count += 1
            
    return igw_count

def aws_key_pair(session, regions):
    """
    Count the total number of EC2 key pairs across all specified regions.

    :param session: Existing boto3 session.
    :param regions: List of AWS regions to check.
    :return: Total count of unique EC2 key pairs across the specified regions.
    """
    unique_key_pairs = set()

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        
        response = ec2_client.describe_key_pairs()
        for key_pair in response['KeyPairs']:
            unique_key_pairs.add(key_pair['KeyPairId'])

    # Return the number of unique EC2 key pairs across all regions
    return len(unique_key_pairs)

def aws_kinesis_firehose_delivery_stream(session, regions):
    

    def is_managed_by_aws(delivery_stream_name):
        aws_managed_prefixes = ['aws', 'AWS']
        return any(delivery_stream_name.startswith(prefix) for prefix in aws_managed_prefixes)

    total_count = 0
    for region in regions:
        firehose_client = session.client('firehose', region_name=region)
        response = firehose_client.list_delivery_streams()
        delivery_stream_names = response.get('DeliveryStreamNames', [])

        user_managed_streams = [
            name for name in delivery_stream_names if not is_managed_by_aws(name)
        ]
        total_count += len(user_managed_streams)

    return total_count

def aws_kinesis_stream(session, regions):
    kinesis_managed_prefixes = [
        'aws/', 'AWS-', 'aws-', 'firehose/', 'Firehose-', 'firehose-'
    ]
    
    def is_internal_stream(stream_name):
        return any(stream_name.startswith(prefix) for prefix in kinesis_managed_prefixes)

    total_stream_count = 0
    checked_global_resources = set()

    for region in regions:
        kinesis_client = session.client('kinesis', region_name=region)
        paginator = kinesis_client.get_paginator('list_streams')

        for page in paginator.paginate():
            for stream_name in page['StreamNames']:
                if not is_internal_stream(stream_name):
                    # Ensure global resources are counted only once
                    if stream_name in checked_global_resources:
                        continue
                    checked_global_resources.add(stream_name)
                    total_stream_count += 1

    return total_stream_count

def aws_kinesis_stream_consumer(session, regions):
    """
    Counts the total number of AWS Kinesis Stream Consumers across provided regions,
    excluding AWS-managed resources.

    Args:
    - session: A Boto3 session object to use for the AWS services.
    - regions: A list of AWS region strings to check for Kinesis Stream Consumers.

    Returns:
    - Total count of Kinesis Stream Consumers excluding AWS-managed resources.
    """
    
    kinesis_consumer_count = 0
    seen_kinesis_consumers = set()
    
    for region in regions:
        client = session.client('kinesis', region_name=region)
        
        try:
            paginator = client.get_paginator('list_stream_consumers')
            for page in paginator.paginate():
                for consumer in page['Consumers']:
                    consumer_arn = consumer['ConsumerARN']
                    if 'aws:' not in consumer_arn:
                        if consumer_arn not in seen_kinesis_consumers:
                            seen_kinesis_consumers.add(consumer_arn)
                            kinesis_consumer_count += 1
        except client.exceptions.ResourceNotFoundException:
            # If the region has no resources, skip to the next region
            continue
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            continue
        
    return kinesis_consumer_count


def aws_kms_alias(session, regions):
    """
    Count the total number of KMS aliases across all specified regions,
    excluding those created and managed by AWS.

    :param session: Existing boto3 session.
    :param regions: List of AWS regions to check.
    :return: Total count of non-AWS-managed KMS aliases across the specified regions.
    """
    
    def is_managed_alias(alias_name):
        return alias_name.startswith('alias/aws/')

    def get_kms_aliases_count(kms_client):
        paginator = kms_client.get_paginator('list_aliases')
        total_aliases = 0

        for page in paginator.paginate():
            for alias in page['Aliases']:
                if not is_managed_alias(alias['AliasName']):
                    total_aliases += 1

        return total_aliases

    total_count = 0

    for region in regions:
        try:
            kms_client = session.client('kms', region_name=region)
            total_count += get_kms_aliases_count(kms_client)
        except (NoCredentialsError, PartialCredentialsError):
            print(f"Skipping region {region} due to credentials error.")

    return total_count

def aws_kms_key(session, regions):
    # kms_client_global = session.client('kms')
    # paginator_global = kms_client_global.get_paginator('list_keys')
    
    kms_count = 0
    global_keys = set()

    # Check KMS keys in each region
    for region in regions:
        kms_client = session.client('kms', region_name=region)
        paginator = kms_client.get_paginator('list_keys')
        
        for page in paginator.paginate():
            for key_id in page['Keys']:
                # Check if the key is managed by AWS
                key_metadata = kms_client.describe_key(KeyId=key_id['KeyId'])
                
                # Skip AWS managed keys
                if key_metadata['KeyMetadata']['KeyManager'] == 'AWS':
                    continue
                
                if key_id['KeyId'] not in global_keys:
                    global_keys.add(key_id['KeyId'])
                    kms_count += 1

    return kms_count

def aws_lambda_alias(session, regions):
    total_alias_count = 0
    global_resources = set()
    
    for region in regions:
        lambda_client = session.client('lambda', region_name=region)
        paginator = lambda_client.get_paginator('list_aliases')
        
        functions_paginator = lambda_client.get_paginator('list_functions')
        for functions_response in functions_paginator.paginate():
            for function in functions_response['Functions']:
                function_name = function['FunctionName']
                
                for alias_response in paginator.paginate(FunctionName=function_name):
                    for alias in alias_response['Aliases']:
                        # Exclude AWS-created resources.
                        if not alias['AliasArn'].startswith('arn:aws:lambda:aws:'):
                            if alias['AliasArn'] not in global_resources:
                                global_resources.add(alias['AliasArn'])
                                total_alias_count += 1

    return total_alias_count

def aws_lambda_code_signing_config(session, regions):
    count = 0
    global_resources = set()
    
    for region in regions:
        lambda_client = session.client('lambda', region_name=region)
        
        paginator = lambda_client.get_paginator('list_code_signing_configs')
        for page in paginator.paginate():
            for config in page['CodeSigningConfigs']:
                if not config['CodeSigningConfigArn'].startswith("arn:aws:lambda:aws:"):
                    if config['CodeSigningConfigArn'] not in global_resources:
                        global_resources.add(config['CodeSigningConfigArn'])
                        count += 1
    
    return count

def aws_lambda_function(session, regions):
    lambda_resource_type = 'AWS::Lambda::Function'
    total_count = 0
    global_resources = set()
    
    for region in regions:
        client = session.client('lambda', region_name=region)
        paginator = client.get_paginator('list_functions')
        for page in paginator.paginate():
            for function in page['Functions']:
                # Exclude AWS-managed resources
                if 'AWSManaged' not in function['FunctionName'] and 'awslambdaruntimemetrics' not in function['FunctionArn']:
                    # Count global resources only once
                    function_arn_parts = function['FunctionArn'].split(':')
                    resource_id = function_arn_parts[-1]
                    if resource_id not in global_resources:
                        total_count += 1
                        global_resources.add(resource_id)
    
    return total_count

def aws_lambda_function_event_invoke_config(session, regions):
    total_count = 0
    seen_config_arns = set()
    
    for region in regions:
        lambda_client = session.client('lambda', region_name=region)
        
        paginator = lambda_client.get_paginator('list_function_event_invoke_configs')
        page_iterator = paginator.paginate()
        
        for page in page_iterator:
            for config in page['FunctionEventInvokeConfigs']:
                config_arn = config['FunctionArn']
                
                if not config_arn.startswith("arn:aws:lambda:*:aws:"):
                    if config_arn not in seen_config_arns:
                        seen_config_arns.add(config_arn)
                        total_count += 1
                        
    return total_count

def aws_lambda_layer_version(session, regions):
    
    
    # Initialize the count
    total_layer_versions = 0
    
    # Loop through each region and count the layer versions
    for region in regions:
        # Create a Lambda client for the given region
        lambda_client = session.client('lambda', region_name=region)
        
        # Use the client's list_layers paginator
        paginator = lambda_client.get_paginator('list_layers')
        
        # Iterate through the pages
        for page in paginator.paginate():
            for layer in page['Layers']:
                # Skip layers that are created and managed by AWS
                if 'arn:aws:lambda' in layer['LayerArn'] and 'aws' in layer['LayerArn']:
                    continue
                
                # Use list_layer_versions to get versions count for each non-AWS-managed layer
                version_paginator = lambda_client.get_paginator('list_layer_versions')
                version_iterator = version_paginator.paginate(LayerName=layer['LayerName'])
                
                for version_page in version_iterator:
                    total_layer_versions += len(version_page['LayerVersions'])
    
    return total_layer_versions

def aws_launch_configuration(session, regions):
    

    def is_aws_managed(resource_name):
        # Identifies AWS managed resources
        return resource_name.startswith('aws-') or resource_name.startswith('AWS-')

    def count_launch_configurations_in_region(region):
        client = session.client('autoscaling', region_name=region)
        paginator = client.get_paginator('describe_launch_configurations')
        launch_configurations = []

        for page in paginator.paginate():
            for lc in page['LaunchConfigurations']:
                if not is_aws_managed(lc['LaunchConfigurationName']):
                    launch_configurations.append(lc)
        
        return len(launch_configurations)

    total_launch_configurations = 0
    counted_regions = set()

    for region in regions:
        region_name = region.strip()
        if region_name not in counted_regions:
            total_launch_configurations += count_launch_configurations_in_region(region_name)
            counted_regions.add(region_name)
    
    return total_launch_configurations

def aws_launch_template(session, regions):
    def is_managed_by_aws(resource):
        if 'OwnerId' in resource and resource['OwnerId'] == 'amazon':
            return True
        if 'Tags' in resource:
            for tag in resource['Tags']:
                if tag['Key'].startswith('aws:'):
                    return True
        return False

    def count_launch_templates_in_region(region):
        ec2_client = session.client('ec2', region_name=region)
        paginator = ec2_client.get_paginator('describe_launch_templates')
        page_iterator = paginator.paginate()
        total_count = 0

        for page in page_iterator:
            for launch_template in page['LaunchTemplates']:
                if not is_managed_by_aws(launch_template):
                    total_count += 1
        
        return total_count

    # Use a set to guarantee each global resource is counted only once
    counted_global_resources = set()
    total_launch_templates = 0
    
    for region in regions:
        total_launch_templates += count_launch_templates_in_region(region)

    return total_launch_templates

def aws_lb(session, regions):
    elbv2_client = session.client('elbv2')
    elb_client = session.client('elb')
    
    total_lbs = 0
    seen_lb_arns = set()
    
    for region in regions:
        # ELBv2 (Application and Network Load Balancers)
        elbv2 = session.client('elbv2', region_name=region)
        paginator_v2 = elbv2.get_paginator('describe_load_balancers')
        for page in paginator_v2.paginate():
            for lb in page['LoadBalancers']:
                if 'managed-by-asg' not in lb['LoadBalancerArn']:
                    arn = lb['LoadBalancerArn']
                    if arn not in seen_lb_arns:
                        total_lbs += 1
                        seen_lb_arns.add(arn)
        
        # ELB (Classic Load Balancers)
        elb = session.client('elb', region_name=region)
        paginator_classic = elb.get_paginator('describe_load_balancers')
        for page in paginator_classic.paginate():
            for lb in page['LoadBalancerDescriptions']:
                arn = lb['LoadBalancerName']
                if arn not in seen_lb_arns:
                    total_lbs += 1
                    seen_lb_arns.add(arn)
    
    # Return the total number of load balancers
    return total_lbs

def aws_lb_listener(session, regions):
    
    

    # Initialize a counter for the total number of load balancer listeners
    total_listeners_count = 0

    # Iterate over each specified region
    for region in regions:
        try:
            # Create an ELBv2 client using the provided session and region
            elbv2_client = session.client('elbv2', region_name=region)

            # Initialize a paginator to handle the response pagination for load balancers
            paginator = elbv2_client.get_paginator('describe_load_balancers')
            page_iterator = paginator.paginate()

            # Iterate through each load balancer
            for page in page_iterator:
                load_balancers = page['LoadBalancers']
                for lb in load_balancers:
                    # Check if the load balancer is managed by AWS
                    if not lb['LoadBalancerArn'].startswith('arn:aws:elasticloadbalancing:'):
                        continue

                    # Fetch listeners for the current load balancer
                    listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])
                    for listener in listeners['Listeners']:
                        # Check if the listener is managed by AWS based on predefined conditions
                        if 'Description' in listener and 'AWS' in listener['Description']:
                            continue

                        # Increment the counter for each unmanaged listener
                        total_listeners_count += 1

        except ClientError as e:
            print(f"An error occurred for region {region}: {e}")

    return total_listeners_count

def aws_lb_listener_certificate(session, regions):
    """
    Count the total number of AWS Load Balancer listener certificates
    across all specified regions excluding resources managed by AWS.
    :param session: Boto3 Session object
    :param regions: List of AWS regions
    :return: Total count of user-managed AWS Load Balancer listener certificates
    """
    total_count = 0
    unique_certificates = set()

    for region in regions:
        elb_client = session.client('elbv2', region_name=region)
        paginator = elb_client.get_paginator('describe_listeners')
        
        for page in paginator.paginate():
            for listener in page['Listeners']:
                certificates = listener.get('Certificates', [])
                for cert in certificates:
                    cert_arn = cert['CertificateArn']
                    
                    # Exclude AWS managed certificates
                    if not cert_arn.startswith('arn:aws:acm') and not cert_arn.startswith('arn:aws:iam') and not 'amazonaws.com' in cert_arn:
                        unique_certificates.add(cert_arn)
    
    total_count = len(unique_certificates)
    return total_count

def aws_lb_listener_rule(session, regions):
    total_rules = 0
    seen_arns = set()  # To ensure global resources are only counted once

    for region in regions:
        elbv2_client = session.client('elbv2', region_name=region)
        
        # Initialize pagination
        paginator = elbv2_client.get_paginator('describe_rules')

        for page in paginator.paginate():           
            for rule in page.get('Rules', []):
                # Skip AWS-managed resources
                if 'managed-by' in rule['Description'].lower():
                    continue
                
                rule_arn = rule['RuleArn']
                
                if rule_arn not in seen_arns:
                    seen_arns.add(rule_arn)
                    total_rules += 1

    return total_rules

def aws_lb_target_group(session, regions):
    def is_not_aws_managed(resource):
        # Example criteria to exclude AWS managed resources, this may need to be adjusted based on actual naming conventions
        aws_managed_prefixes = ['aws', 'amazon', 'eks']
        return not any(resource['TargetGroupName'].startswith(prefix) for prefix in aws_managed_prefixes)
    
    total_count = 0
    counted_resources = set()

    for region in regions:
        elbv2_client = session.client('elbv2', region_name=region)
        paginator = elbv2_client.get_paginator('describe_target_groups')
        for page in paginator.paginate():
            for target_group in page['TargetGroups']:
                arn = target_group['TargetGroupArn']
                if is_not_aws_managed(target_group) and arn not in counted_resources:
                    counted_resources.add(arn)
                    total_count += 1

    return total_count

def aws_lightsail_instance(session, regions):
    
    
    # Initialize a counter for total instances
    total_instances = 0
    
    # Loop through each AWS region
    for region in regions:
        # Create a Lightsail client for the region
        lightsail_client = session.client('lightsail', region_name=region)
        
        # List all instances in the current region
        paginator = lightsail_client.get_paginator('get_instances')
        for page in paginator.paginate():
            for instance in page['instances']:
                # Exclude instances that are created and managed by AWS
                # Assuming instances managed by AWS would have a specific tag or naming convention
                # This is a placeholder check, adjust based on your actual criteria
                if "aws:" not in instance['name']:
                    total_instances += 1
    
    return total_instances

def aws_mq_broker(session, regions):
    # Initialize the count of MQ brokers
    total_brokers = 0

    # Iterate over each region
    for region in regions:
        # Create an AWS MQ client for the specific region
        mq_client = session.client('mq', region_name=region)
        
        # List all brokers in the region
        brokers = mq_client.list_brokers()
        
        # Filter out AWS managed brokers and count the rest
        for broker in brokers['BrokerSummaries']:
            if not broker['BrokerName'].startswith('AWS'):
                total_brokers += 1

    return total_brokers

def aws_mq_configuration(session, regions):
    """
    Counts the total number of AWS MQ configurations across specified regions,
    excluding resources created and managed by AWS.
    
    Parameters:
    - session: an existing boto3 session.
    - regions: a list of AWS region names as strings.
    
    Returns:
    - int: Total count of user-created AWS MQ configurations across all regions.
    """
    # Import necessary boto3 client
    
    
    # Initialize count
    total_mq_configurations = 0
    
    for region in regions:
        # Create a client for AWS MQ in the specific region
        client = session.client('mq', region_name=region)
        
        # List configurations
        response = client.list_configurations()
        
        # Filter out configurations managed by AWS
        user_configurations = [config for config in response['Configurations'] if not config['EngineType'].startswith('managed')]
        
        # Add to total count
        total_mq_configurations += len(user_configurations)
    
    return total_mq_configurations

def aws_msk_cluster(session, regions):
    msk_count = 0
    managed_prefixes = ('aws', 'amzn', 'eks')

    for region in regions:
        msk_client = session.client('kafka', region_name=region)
        clusters_response = msk_client.list_clusters(
            ClusterNameFilter='all'
        )
        
        for cluster in clusters_response['ClusterInfoList']:
            cluster_name = cluster['ClusterName']
            if not any(cluster_name.startswith(prefix) for prefix in managed_prefixes):
                msk_count += 1

    return msk_count

def aws_msk_configuration(session, regions):
    client = session.client('kafka')
    
    def is_user_managed(configuration):
        # Assuming that AWS-managed configurations have some identifying characteristic.
        # Customize the condition appropriately
        return not configuration.get('Name', '').startswith('AWS')
    
    configuration_names = set()
    
    for region in regions:
        regional_client = session.client('kafka', region_name=region)
        paginator = regional_client.get_paginator('list_configurations')
        
        for page in paginator.paginate():
            configurations = page.get('Configurations', [])
            
            for config in configurations:
                if is_user_managed(config):
                    configuration_names.add(config['Name'])
    
    total_count = len(configuration_names)
    return total_count

def aws_mwaa_environment(session, regions):
    exclude_prefixes = ['aws-']  # Add any other prefixes that AWS uses for managed resources

    def is_managed_by_aws(name):
        return any(name.startswith(prefix) for prefix in exclude_prefixes)

    mwaa_environment_count = 0
    seen_global_resources = set()

    for region in regions:
        mwaa_client = session.client('mwaa', region_name=region)
        paginator = mwaa_client.get_paginator('list_environments')
        response_iterator = paginator.paginate()
        
        for response in response_iterator:
            environments = response.get('Environments', [])
            for environment in environments:
                if is_managed_by_aws(environment):
                    continue
                if environment not in seen_global_resources:
                    seen_global_resources.add(environment)
                    mwaa_environment_count += 1

    return mwaa_environment_count

def aws_nat_gateway(session, regions):
    

    total_nat_gateways = 0

    for region in regions:
        ec2 = session.client('ec2', region_name=region)
        response = ec2.describe_nat_gateways()
        
        for nat_gateway in response.get('NatGateways', []):
            total_nat_gateways += 1

    return total_nat_gateways

def aws_neptune_cluster(session, regions):
    neptune_cluster_count = 0
    seen_clusters = set()
    
    for region in regions:
        neptune_client = session.client('neptune', region_name=region)
        
        paginator = neptune_client.get_paginator('describe_db_clusters')
        for page in paginator.paginate():
            for cluster in page['DBClusters']:
                cluster_arn = cluster['DBClusterArn']
                
                # Check if the cluster is not managed by AWS
                if 'aws:' not in cluster_arn:
                    if cluster_arn not in seen_clusters:
                        seen_clusters.add(cluster_arn)
                        neptune_cluster_count += 1
    return neptune_cluster_count

def aws_neptune_cluster_instance(session, regions):
    total_instances = 0
    excluded_engines = set(["neptune"])

    for region in regions:
        neptune_client = session.client('neptune', region_name=region)
        try:
            response = neptune_client.describe_db_instances()
            for db_instance in response['DBInstances']:
                if db_instance['Engine'] not in excluded_engines:
                    total_instances += 1
        except Exception as e:
            print(f"Error fetching instances in region {region}: {str(e)}")
    
    return total_instances

def aws_neptune_cluster_parameter_group(session, regions):
    neptune_param_group_count = 0
    seen_param_groups = set()  # to ensure global resources are counted only once
    
    for region in regions:
        neptune_client = session.client('neptune', region_name=region)
        paginator = neptune_client.get_paginator('describe_db_cluster_parameter_groups')
        
        for page in paginator.paginate():
            for param_group in page['DBClusterParameterGroups']:
                param_group_name = param_group['DBClusterParameterGroupName']
                
                # Check if parameter group is not managed by AWS
                if not param_group_name.startswith("default.") and param_group_name not in seen_param_groups:
                    neptune_param_group_count += 1
                    seen_param_groups.add(param_group_name)
    
    return neptune_param_group_count

def aws_neptune_parameter_group(session, regions):
    """
    Count the total number of Neptune parameter groups across all specified regions,
    excluding resources managed by AWS.
    
    Parameters:
    - session: A Boto3 session object.
    - regions: A list of AWS region names as strings.
    
    Returns:
    - count: The total number of Neptune parameter groups excluding AWS managed ones.
    """
    try:
        total_count = 0
        
        for region in regions:
            neptune_client = session.client('neptune', region_name=region)
            paginator = neptune_client.get_paginator('describe_db_parameter_groups')
            for page in paginator.paginate():
                for param_group in page['DBParameterGroups']:
                    # Exclude parameter groups managed by AWS
                    if not param_group['DBParameterGroupName'].startswith('aws:'):
                        total_count += 1
        
        return total_count

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def aws_network_acl(session, regions):
    global_acls = set()
    total_acl_count = 0

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        acls = ec2_client.describe_network_acls()['NetworkAcls']

        for acl in acls:
            # Exclude AWS managed resources
            if acl['IsDefault']:
                continue
            # Check for global resources (e.g., ACLs that might span multiple regions)
            acl_id = acl['NetworkAclId']
            if acl_id not in global_acls:
                global_acls.add(acl_id)
                total_acl_count += 1

    return total_acl_count

def aws_network_interface(session, regions):
    

    def is_aws_managed(interface):
        # Implement a check to see if the network interface is AWS managed
        # This could be based on Tags, Description, OwnerId, etc.
        # Example check: 'aws:' prefix in Description
        description = interface.get('Description', '')
        return description.startswith('aws:')

    total_count = 0

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        paginator = ec2_client.get_paginator('describe_network_interfaces')
        for page in paginator.paginate():
            for interface in page['NetworkInterfaces']:
                if not is_aws_managed(interface):
                    total_count += 1

    return total_count

def aws_networkfirewall_firewall(session, regions):
    """
    Count the total number of AWS Network Firewalls across all regions.
    
    Parameters:
    session (boto3.Session): an existing boto3 session
    regions (list): a list of AWS regions
    
    Returns:
    int: the total count of AWS Network Firewalls excluding those managed by AWS.
    """
    firewall_count = 0
    for region in regions:
        client = session.client('network-firewall', region_name=region)
        try:
            # Paginate through the firewalls
            paginator = client.get_paginator('list_firewalls')
            for page in paginator.paginate():
                for firewall in page['Firewalls']:
                    # Filter out the AWS-managed firewalls based on a specific criteria
                    # that identifies them (as an example using a prefix 'aws-')
                    if not firewall['FirewallName'].startswith('aws-'):
                        firewall_count += 1
        except client.exceptions.ResourceNotFoundException:
            # If no firewalls exist in the region
            pass
        except Exception as e:
            print(f"An error occurred in region {region}: {e}")
    
    return firewall_count

def aws_prometheus_rule_group_namespace(session, regions):
    

    # Initialize a counter for the total number of rule group namespaces
    total_rule_group_namespaces = 0

    # Iterate over each region
    for region in regions:
        # Create a new client for Amazon Managed Service for Prometheus in the given region
        amp_client = session.client('amp', region_name=region)

        # List workspaces in the given region
        response = amp_client.list_workspaces()
        workspaces = response.get('workspaces', [])

        # Iterate over each workspace and list rule group namespaces
        for workspace in workspaces:
            if not workspace.get('arn').startswith('arn:aws:amp:::'): # Exclude AWS-created resources
                workspace_id = workspace['workspaceId']
                
                # List rule groups namespaces in the current workspace
                response = amp_client.list_rule_groups_namespaces(workspaceId=workspace_id)
                rule_group_namespaces = response.get('ruleGroupsNamespaces', [])
                
                # Add the number of rule group namespaces to the total count
                total_rule_group_namespaces += len(rule_group_namespaces)
    
    return total_rule_group_namespaces

def aws_prometheus_workspace(session, regions):
    total_count = 0

    for region in regions:
        client = session.client('amp', region_name=region)
        
        paginator = client.get_paginator('list_workspaces')
        page_iterator = paginator.paginate()

        for page in page_iterator:
            for workspace in page['workspaces']:
                if not workspace.get('tags', {}).get('aws:cloudformation:stack-name') and not workspace['alias'].startswith("aws"):
                    total_count += 1

    return total_count

def aws_quicksight_data_source(session, regions):
    def get_data_sources(client):
        paginator = client.get_paginator('list_data_sources')
        data_sources = []
        for page in paginator.paginate():
            data_sources.extend(page['DataSources'])
        return [ds for ds in data_sources if not ds['Arn'].startswith('arn:aws:quicksight:aws:')]

    quicksight_client = session.client('quicksight')
    
    datasource_count = 0
    seen_data_sources = set()
    for region in regions:
        regional_client = session.client('quicksight', region_name=region)
        data_sources = get_data_sources(regional_client)
        
        for ds in data_sources:
            if ds['DataSourceId'] not in seen_data_sources:
                seen_data_sources.add(ds['DataSourceId'])
                datasource_count += 1
    
    return datasource_count

def aws_quicksight_group(session, regions):
    quicksight_client = session.client('quicksight')
    account_id = session.client('sts').get_caller_identity().get('Account')
    group_count = 0
    counted_groups = set()  # To keep track of unique global resources
    
    for region in regions:
        quicksight_client = session.client('quicksight', region_name=region)
        paginator = quicksight_client.get_paginator('list_groups')
        for page in paginator.paginate(AwsAccountId=account_id):
            for group in page['GroupList']:
                group_arn = group['Arn']
                # Assuming the check for "created and managed by AWS" is by name prefix or similar criteria
                if not group['Name'].startswith('AWS_'):
                    if group_arn not in counted_groups:
                        counted_groups.add(group_arn)
                        group_count += 1
    
    return group_count

def aws_ram_resource_share(session, regions):
    """
    Count the total number of aws_ram_resource_share across all specified regions,
    excluding resources created and managed by AWS, and avoiding double-counting global resources.
    """
    
    

    # Initialize a set to track the unique global resource ARNs
    global_resources = set()
    total_count = 0
    
    for region in regions:
        # Initialize the RAM client for each region
        client = session.client('ram', region_name=region)

        # Initialize the paginator for listing resource shares
        paginator = client.get_paginator('get_resource_shares')

        # Iterate over all pages of results
        for page in paginator.paginate(resourceOwner='SELF'):
            for resource_share in page['resourceShares']:
                arn = resource_share['resourceShareArn']
                
                # Check if the resource is managed by AWS by examining the tags
                tags_response = client.list_tags_for_resource(
                    resourceArn=arn
                )
                
                aws_managed = any(
                    tag['Key'].startswith('aws:') for tag in tags_response['tags']
                )
                
                # Global ARNs should only be counted once
                if 'global' in arn and arn not in global_resources:
                    if not aws_managed:
                        global_resources.add(arn)
                        total_count += 1
                # Count regional ARNs normally
                elif 'global' not in arn:
                    if not aws_managed:
                        total_count += 1

    return total_count

def aws_rds_cluster(session, regions):
    

    cluster_count = 0

    for region in regions:
        rds_client = session.client('rds', region_name=region)
        paginator = rds_client.get_paginator('describe_db_clusters')
        
        for page in paginator.paginate():
            for cluster in page.get('DBClusters', []):
                # Exclude clusters managed by AWS
                if not cluster.get('DBClusterArn', '').startswith('arn:aws:rds'):
                    continue
                cluster_count += 1

    return cluster_count

def aws_rds_cluster_endpoint(session, regions):
    total_aws_rds_cluster_endpoints = 0
    seen_global_resources = set()

    for region in regions:
        rds_client = session.client('rds', region_name=region)
        paginator = rds_client.get_paginator('describe_db_clusters')
        for page in paginator.paginate():
            for db_cluster in page['DBClusters']:
                # Exclude resources created and managed by AWS
                if 'aws:resource:tag:aws:createdBy' not in db_cluster['DBClusterArn']:
                    total_aws_rds_cluster_endpoints += 1
        
    return total_aws_rds_cluster_endpoints

def aws_rds_cluster_parameter_group(session, regions):
    # Import necessary boto3 module
    
    
    # Initialize a set to keep track of unique global parameter groups
    global_param_groups = set()
    
    # Initialize counters for RDS cluster parameter groups
    total_count = 0
    
    for region in regions:
        # Create a regional RDS client from the given session
        rds_client = session.client('rds', region_name=region)
        
        # Paginate through all available RDS cluster parameter groups
        paginator = rds_client.get_paginator('describe_db_cluster_parameter_groups')
        for page in paginator.paginate():
            for param_group in page['DBClusterParameterGroups']:
                # Exclude resources created and managed by AWS
                if 'aws:' not in param_group['DBClusterParameterGroupName']:
                    param_group_name = param_group['DBClusterParameterGroupName']
                    parameter_group_family = param_group['DBParameterGroupFamily']
                    
                    # Check if the parameter group is global
                    if parameter_group_family in global_param_groups:
                        continue
                    
                    # Add global parameter groups to the set
                    if parameter_group_family.startswith('aurora'):
                        global_param_groups.add(parameter_group_family)
                    # Otherwise increment the total count
                    else:
                        total_count += 1

    # Increment the total count for unique global parameter groups
    total_count += len(global_param_groups)
    
    # Return the total number of RDS cluster parameter groups
    return total_count

def aws_rds_global_cluster(session, regions):
    """
    Count the total number of global clusters in AWS RDS across all given regions, excluding AWS managed clusters.
    
    Parameters:
    - session (boto3.Session): The boto3 session.
    - regions (list of str): List of AWS regions to check.

    Returns:
    - int: Total count of global clusters.
    """
    rds_client = session.client('rds')
    global_clusters = set()

    for region in regions:
        regional_rds_client = session.client('rds', region_name=region)
        paginator = regional_rds_client.get_paginator('describe_global_clusters')
        for page in paginator.paginate():
            for global_cluster in page.get('GlobalClusters', []):
                if not global_cluster.get('GlobalClusterArn', '').startswith('arn:aws:rds:global:'):
                    global_clusters.add(global_cluster['GlobalClusterIdentifier'])

    return len(global_clusters)

def aws_redshift_cluster(session, regions):
    total_clusters = 0

    for region in regions:
        redshift_client = session.client('redshift', region_name=region)
        
        # Use the describe_clusters API call to list the Redshift clusters
        clusters_response = redshift_client.describe_clusters()
        clusters = clusters_response.get('Clusters', [])
        
        # Count the clusters that are user-managed (exclude AWS-managed resources)
        # Assuming that AWS-managed clusters would have a specific characteristic,
        # here we're using 'ClusterIdentifier' that does not contain 'aws'
        user_clusters = [cluster for cluster in clusters if 'aws' not in cluster['ClusterIdentifier'].lower()]
        total_clusters += len(user_clusters)
    
    return total_clusters

def aws_redshift_parameter_group(session, regions):
    
    
    def is_custom_parameter_group(parameter_group):
        # assuming that managed by AWS groups start with 'aws-' or some specific pattern
        return not parameter_group['ParameterGroupName'].startswith('aws-')

    total_count = 0
    
    for region in regions:
        # Use session to create a Redshift client for the specified region
        redshift_client = session.client('redshift', region_name=region)
        
        # Use the describe_cluster_parameter_groups API call to list the parameter groups
        response = redshift_client.describe_cluster_parameter_groups()
        
        # Filter out any parameter groups that are created and managed by AWS
        custom_param_groups = [
            pg for pg in response['ParameterGroups'] if is_custom_parameter_group(pg)
        ]
        
        total_count += len(custom_param_groups)
    
    return total_count

def aws_redshift_subnet_group(session, regions):
    redshift_subnet_group_count = 0

    for region in regions:
        redshift_client = session.client('redshift', region_name=region)
        
        try:
            response = redshift_client.describe_cluster_subnet_groups()
            
            for subnet_group in response['ClusterSubnetGroups']:
                # Only count the user-managed subnet groups
                if not subnet_group['ClusterSubnetGroupName'].startswith('aws-'):
                    redshift_subnet_group_count += 1
        except Exception as e:
            print(f"An error occurred in region {region}: {e}")

    return redshift_subnet_group_count

def aws_route_table(session, regions):
    total_count = 0
    for region in regions:
        regional_client = session.client('ec2', region_name=region)
        paginator = regional_client.get_paginator('describe_route_tables')
        page_iterator = paginator.paginate()
        
        for page in page_iterator:
            for route_table in page['RouteTables']:
                is_managed_by_aws = False
                
                if 'Tags' in route_table:    
                    for tag in route_table['Tags']:
                        if tag['Key'].startswith("aws:"):
                            is_managed_by_aws = True
                            break
                
                if not is_managed_by_aws:
                    total_count += 1
    
    # Account for global resources only once
    # global_resources = count_global_resources(total_count)
    return total_count

# def count_global_resources(total_resources):
#     # Logic for deduplication of global resources if needed
#     # Returning total_resources directly as global resources are
#     # assumed to be counting only once for the sake of this function.
#     return total_resources

def aws_route_table_association(session, regions):
    """
    Count the total number of route table associations across all given AWS regions.
    Exclude resources created and managed by AWS.
    
    Parameters:
    session (boto3.Session): An existing boto3 session.
    regions (list): List of AWS regions to check.
    
    Returns:
    int: Total count of route table associations, excluding AWS-managed resources.
    """
    
    total_count = 0
    
    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        
        # Get all route tables in the region
        route_tables = ec2_client.describe_route_tables()
        
        for route_table in route_tables['RouteTables']:
            # Check if the route table is managed by AWS
            is_managed_by_aws = any(
                tag['Key'].startswith('aws:')
                for tag in route_table.get('Tags', [])
            )
            
            if not is_managed_by_aws:
                # Count the number of associations
                associations = route_table.get('Associations', [])
                total_count += len(associations)
    
    return total_count

def aws_route53_record(session, regions):
    route53_client = session.client('route53')
    total_record_count = 0

    # List all hosted zones (Route 53 is global, so we only need to do this once)
    hosted_zones = route53_client.list_hosted_zones()

    for zone in hosted_zones['HostedZones']:
        zone_id = zone['Id']
        
        # Assuming we need to list all records in each zone
        paginator = route53_client.get_paginator('list_resource_record_sets')
        record_iterator = paginator.paginate(HostedZoneId=zone_id)
        
        for page in record_iterator:
            for record_set in page['ResourceRecordSets']:
                # Exclude AWS-managed resources by filtering specific names or types if needed
                if not is_aws_managed(record_set):
                    total_record_count += 1
    
    return total_record_count

def is_aws_managed(record_set):
    # Implement logic to determine if the record set is AWS-managed
    # For simplicity, let's assume we exclude records with certain patterns or types
    # This logic might need adjustments based on actual AWS-managed record names/patterns
    aws_managed_types = ['NS', 'SOA']
    if record_set['Type'] in aws_managed_types:
        return True
    # Add more conditions based on AWS managed name patterns if needed
    return False

def aws_route53_zone(session, regions):
    
    
    # Route53 is global, it doesn't need regional endpoints.
    client = session.client('route53')
    
    response = client.list_hosted_zones()

    # Iterate over hosted zones and count only user managed zones
    count = 0
    for zone in response['HostedZones']:
        if '"aws"' not in zone['Name']:
            count += 1
    
    return count

def aws_s3_bucket(session, regions):
    
    
    def is_managed_by_aws(bucket_name):
        managed_prefixes = ['aws-', 'awslogs', 'awsexamplebucket']
        return any(bucket_name.startswith(prefix) for prefix in managed_prefixes)
    
    s3 = session.client('s3')
    bucket_set = set()
    
    for region in regions:
        s3 = session.client('s3', region_name=region)
        response = s3.list_buckets()
        
        for bucket in response['Buckets']:
            if not is_managed_by_aws(bucket['Name']):
                bucket_set.add(bucket['Name'])
                
    return len(bucket_set)

def aws_s3_bucket_accelerate_configuration(session, regions):
    bucket_count = 0
    global_buckets = set()
    
    for region in regions:
        try:
            s3_client = session.client('s3', region_name=region)
            response = s3_client.list_buckets()
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                
                # Skip buckets that are created and managed by AWS
                if bucket_name.startswith('aws-') or bucket_name.startswith('elasticbeanstalk-'):
                    continue
                
                # Check if the bucket is global (exists in another region)
                if bucket_name in global_buckets:
                    continue
                
                try:
                    accel_config = s3_client.get_bucket_accelerate_configuration(Bucket=bucket_name)
                    if accel_config['Status'] == 'Enabled':
                        bucket_count += 1
                        global_buckets.add(bucket_name)
                except ClientError as e:
                    # If the error is because the bucket is not present in the region, ignore and continue
                    if e.response['Error']['Code'] in ['NoSuchBucket', 'AccessDenied']:
                        continue
                    else:
                        raise e

        except ClientError as e:
            # Handle exception for client creation or bucket listing
            print(f"An error occurred in region {region}: {e}")
            continue
    
    return bucket_count

def aws_s3_bucket_acl(session, regions):
    # Create a set to store unique global bucket names
    global_buckets = set()
    
    # Initialize the counter for bucket ACLs 
    total_acl_count = 0
    
    for region in regions:
        s3_client = session.client('s3', region_name=region)
        
        # List all buckets in the region
        response = s3_client.list_buckets()
        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']
            
            # Skip buckets managed by AWS
            if bucket_name.startswith('aws-') or bucket_name.startswith('elasticbeanstalk-'):
                continue
            
            # To avoid recounting global buckets
            if bucket_name in global_buckets:
                continue
            
            global_buckets.add(bucket_name)
            
            # Get ACLs for the bucket
            acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
            acl_count = len(acl_response.get('Grants', []))
            
            # Add the ACL count to total
            total_acl_count += acl_count
    
    return total_acl_count

def aws_s3_bucket_cors_configuration(session, regions):
    s3_cors_count = 0
    seen_buckets = set()  # To ensure global resources are only counted once

    for region in regions:
        s3_client = session.client('s3', region_name=region)
        response = s3_client.list_buckets()
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            if bucket_name in seen_buckets:
                continue
            
            # Mark this bucket as seen to ensure it is not counted multiple times 
            # in case it's a global resource
            seen_buckets.add(bucket_name)
            
            # Get the bucket's location, and if it doesn't match the region, skip it.
            # This is to ensure we're only counting buckets in the current region.
            bucket_location = s3_client.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
            if bucket_location != region and bucket_location is not None:
                continue
            
            try:
                # Attempt to get the bucket's CORS configuration
                s3_client.get_bucket_cors(Bucket=bucket_name)
                s3_cors_count += 1  # Increment count for each bucket with CORS configuration
            except s3_client.exceptions.NoSuchCORSConfiguration:
                # If no CORS configuration exists, we simply move to the next bucket
                pass

    return s3_cors_count

def aws_s3_bucket_lifecycle_configuration(session, regions):
    counted_resources = set()
    total_lifecycle_configurations = 0

    for region in regions:
        s3_client = session.client('s3', region_name=region)
        buckets_response = s3_client.list_buckets()

        for bucket in buckets_response['Buckets']:
            bucket_name = bucket['Name']
            try:
                lifecycle_configuration = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                rules = lifecycle_configuration.get('Rules', [])
                for rule in rules:
                    if 'ID' in rule and 'aws' not in rule['ID'].lower():
                        if bucket_name not in counted_resources:
                            counted_resources.add(bucket_name)
                            total_lifecycle_configurations += 1
            except s3_client.exceptions.NoSuchLifecycleConfiguration:
                continue

    return total_lifecycle_configurations

def aws_s3_bucket_logging(session, regions):
    # Initialize a set to keep track of unique bucket names
    unique_buckets = set()
    
    # Loop through each region
    for region in regions:
        s3_client = session.client('s3', region_name=region)
        
        # List all buckets
        response = s3_client.list_buckets()
        
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            
            # Get the bucket location to ensure we count global resources only once
            bucket_location = s3_client.get_bucket_location(Bucket=bucket_name)
            bucket_region = bucket_location['LocationConstraint']
            
            if bucket_region is None:
                bucket_region = 'us-east-1'  # Us-east-1 has a special case for LocationConstraint
            
            # Check if the bucket is in the current region
            if bucket_region == region:
                # Exclude AWS managed buckets
                if not bucket_name.startswith(('aws-', 'awseb-', 'elasticbeanstalk-', 'aws-glue-vars-')):
                    unique_buckets.add(bucket_name)
    
    return len(unique_buckets)

def aws_s3_bucket_object_lock_configuration(session, regions):
    s3_client = session.client('s3')
    total_aws_s3_bucket_object_lock_configuration = 0
    visited_buckets = set()

    for region in regions:
        s3_client = session.client('s3', region_name=region)
        response = s3_client.list_buckets()
        buckets = response['Buckets']

        for bucket in buckets:
            bucket_name = bucket['Name']

            if bucket_name in visited_buckets:
                continue

            visited_buckets.add(bucket_name)

            try:
                lock_config = s3_client.get_object_lock_configuration(
                    Bucket=bucket_name
                )

                if 'ObjectLockConfiguration' in lock_config:
                    total_aws_s3_bucket_object_lock_configuration += 1
            except s3_client.exceptions.NoSuchBucket:
                continue
            except s3_client.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']

                if error_code != 'InvalidRequest':
                    continue

    return total_aws_s3_bucket_object_lock_configuration

def aws_s3_bucket_ownership_controls(session, regions):
    total_ownership_controls = 0

    for region in regions:
        s3_client = session.client('s3', region_name=region)
        try:
            # List all buckets in the account
            buckets = s3_client.list_buckets().get('Buckets', [])
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    # Check the bucket's region to ensure it belongs to the current region
                    bucket_location = s3_client.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
                    if bucket_location == region or (region == 'us-east-1' and bucket_location is None):
                        # Get bucket ownership controls using the s3 client directly
                        response = s3_client.get_bucket_ownership_controls(Bucket=bucket_name)
                        if 'OwnershipControls' in response:
                            total_ownership_controls += 1
                except s3_client.exceptions.NoSuchBucketOwnershipControls:
                    print(f"No ownership controls found for bucket {bucket_name} in region {region}")
                except Exception as e:
                    print(f"Error fetching ownership controls for bucket {bucket_name} in region {region}: {str(e)}")
        except Exception as e:
            print(f"Error listing buckets for region {region}: {str(e)}")
    
    return total_ownership_controls


def aws_s3_bucket_policy(session, regions):
    
    def get_bucket_policy_count(s3_client):
        bucket_policy_count = 0
        try:
            buckets = s3_client.list_buckets()
            for bucket in buckets['Buckets']:
                try:
                    s3_client.get_bucket_policy(Bucket=bucket['Name'])
                    bucket_policy_count += 1
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                        pass
                    else:
                        raise e
        except ClientError as e:
            print(f"Error listing buckets: {e}")
        return bucket_policy_count
    
    total_bucket_policy_count = 0
    counted_buckets = set()
    
    for region in regions:
        s3_client = session.client('s3', region_name=region)
        
        bucket_policy_count = get_bucket_policy_count(s3_client)
        total_bucket_policy_count += bucket_policy_count
    
    return total_bucket_policy_count

# def aws_s3_bucket_public_access_block(session, regions):
#     total_public_access_blocks = 0
    
#     # Use STS to get the account ID
#     sts_client = session.client('sts')
#     account_id = sts_client.get_caller_identity()['Account']
    
#     for region in regions:
#         s3_control_client = session.client('s3control', region_name=region)
#         try:
#             # Fetch public access block configuration for the account
#             response = s3_control_client.get_public_access_block(AccountId=account_id)
#             if 'PublicAccessBlockConfiguration' in response:
#                 total_public_access_blocks += 1
#         except s3_control_client.exceptions.NoSuchPublicAccessBlockConfiguration:
#             print(f"No public access block configuration found for region {region}")
#         except Exception as e:
#             print(f"Error fetching public access block configurations for region {region}: {str(e)}")
    
#     return total_public_access_blocks

def aws_s3_bucket_public_access_block(session, regions):
    total_public_access_blocks = 0
    
    # Use STS to get the account ID
    sts_client = session.client('sts', regions[0])
    account_id = sts_client.get_caller_identity()['Account']
    
    s3_control_client = session.client('s3control', regions[0])
    try:
        # Fetch public access block configuration for the account
        response = s3_control_client.get_public_access_block(AccountId=account_id)
        if 'PublicAccessBlockConfiguration' in response:
            total_public_access_blocks += 1
    except s3_control_client.exceptions.NoSuchPublicAccessBlockConfiguration:
        print("No public access block configuration found for the account")
    except Exception as e:
        print(f"Error fetching public access block configurations: {str(e)}")
    
    return total_public_access_blocks

def aws_s3_bucket_replication_configuration(session, regions):
    s3 = session.client('s3')
    visited_buckets = set()
    total_replications = 0
    
    for region in regions:
        s3 = session.client('s3', region_name=region)
        response = s3.list_buckets()
        
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            
            if bucket_name in visited_buckets:
                continue
            
            try:
                replication = s3.get_bucket_replication(Bucket=bucket_name)
                total_replications += len(replication.get('ReplicationConfiguration', {}).get('Rules', []))
            except s3.exceptions.ClientError as e:
                # Continue if replication configuration does not exist or access is denied
                if e.response['Error']['Code'] in ('ReplicationConfigurationNotFoundError', 'AccessDenied'):
                    continue
                else:
                    raise
            
            visited_buckets.add(bucket_name)
    
    return total_replications

def aws_s3_bucket_request_payment_configuration(session, regions):
    def is_aws_managed(bucket_name):
        return bucket_name.startswith('aws-') or bucket_name.startswith('amzn-')

    s3 = session.client('s3')
    total_request_payment_configurations = 0

    unique_global_buckets = set()

    for region in regions:
        s3 = session.client('s3', region_name=region)
        paginator = s3.get_paginator('list_buckets')

        for page in paginator.paginate():
            for bucket in page['Buckets']:
                bucket_name = bucket['Name']
                if not is_aws_managed(bucket_name):
                    if bucket_name in unique_global_buckets:
                        continue
                    try:
                        s3.get_bucket_request_payment(Bucket=bucket_name)
                        total_request_payment_configurations += 1
                        unique_global_buckets.add(bucket_name)
                    except s3.exceptions.ClientError as e:
                        if e.response['Error']['Code'] == 'RequestPaymentConfigurationNotFoundError':
                            continue
                        else:
                            raise

    return total_request_payment_configurations

def aws_s3_bucket_server_side_encryption_configuration(session, regions):
    """
    Count the total number of S3 buckets with server-side encryption configuration across all regions.
    Excludes any resources that are created and managed by AWS.
    
    Args:
        session (boto3.Session): Existing Boto3 session.
        regions (list): List of AWS regions to check.
    
    Returns:
        int: Total count of S3 buckets with server-side encryption configuration.
    """
    s3 = session.client('s3')
    total_count = 0
    checked_buckets = set()

    for region in regions:
        regional_s3 = session.client('s3', region_name=region)
        response = regional_s3.list_buckets()

        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']

            # Check if the bucket is already checked to avoid duplicate counting of global resources
            if bucket_name not in checked_buckets:
                checked_buckets.add(bucket_name)

                try:
                    encryption_config = s3.get_bucket_encryption(Bucket=bucket_name)
                    total_count += 1
                except s3.exceptions.ClientError as e:
                    # Ignore buckets without server-side encryption configuration
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        continue
                
    return total_count

def aws_s3_bucket_versioning(session, regions):
    # Initialize a set to keep track of unique bucket names
    unique_buckets = set()

    for region in regions:
        # Create an S3 client for the specified region
        s3_client = session.client('s3', region_name=region)

        # List all the buckets
        response = s3_client.list_buckets()

        for bucket in response['Buckets']:
            # Get the bucket name
            bucket_name = bucket['Name']
            
            # Check if the bucket is managed by AWS
            if not bucket_name.startswith("aws-"):
                # Add to the set of unique buckets
                unique_buckets.add(bucket_name)
                
                # Get bucket versioning status
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                
                # Only count versioned buckets
                if versioning.get('Status') == 'Enabled':
                    unique_buckets.add(bucket_name)

    # Return the total number of unique versioned buckets across all regions
    return len(unique_buckets)

def aws_s3_bucket_website_configuration(session, regions):
    """
    Counts the total number of AWS S3 bucket website configurations across all specified regions,
    excluding resources that are created and managed by AWS.
    
    :param session: The Boto3 session object
    :param regions: A list of AWS region names
    :return: The count of S3 bucket website configurations
    """
    s3_client = session.client('s3')
    s3_control_client = session.client('s3control')
    
    global_configured_buckets = set()
    
    def is_managed_by_aws(bucket_name):
        # Simple heuristic to detect AWS managed resources
        return bucket_name.startswith('aws') or bucket_name.startswith('cloudtrail')
    
    for region in regions:
        region_s3_client = session.client('s3', region_name=region)
        response = region_s3_client.list_buckets()
        
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            
            if is_managed_by_aws(bucket_name):
                continue
            
            try:
                region_s3_client.get_bucket_website(Bucket=bucket_name)
                # Use a global client to avoid duplicates due to global bucket namespace
                _, bucket_region_name = s3_client.get_bucket_location(Bucket=bucket_name)['LocationConstraint'], region
                
                if bucket_name not in global_configured_buckets:
                    global_configured_buckets.add(bucket_name)
            except region_s3_client.exceptions.NoSuchWebsiteConfiguration:
                continue
            except region_s3_client.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ('AccessDenied', 'AllAccessDisabled'):
                    continue
                else:
                    raise e

    return len(global_configured_buckets)

def aws_sagemaker_app(session, regions):
    

    total_count = 0

    for region in regions:
        sagemaker_client = session.client('sagemaker', region_name=region)
        paginator = sagemaker_client.get_paginator('list_apps')
        for page in paginator.paginate():
            for app in page['Apps']:
                if not app['AppName'].startswith('aws-'):
                    total_count += 1

    return total_count

def aws_sagemaker_code_repository(session, regions):
    total_code_repositories = 0

    for region in regions:
        sagemaker_client = session.client('sagemaker', region_name=region)
        paginator = sagemaker_client.get_paginator('list_code_repositories')
        for page in paginator.paginate():
            for code_repository in page['CodeRepositorySummaryList']:
                # Check if the resource is not AWS managed
                if not code_repository.get('CodeRepositoryArn', '').startswith('arn:aws:sagemaker:aws-'):
                    total_code_repositories += 1
    
    return total_code_repositories

def aws_sagemaker_domain(session, regions):
    

    def is_not_aws_managed(domain_name):
        # Adjust the string patterns based on actual AWS managed domain naming conventions
        aws_managed_patterns = ['aws-', 'amazon-', 'awsmanaged-']
        return not any(domain_name.startswith(pattern) for pattern in aws_managed_patterns)

    sagemaker_domains_count = 0
    visited_domains = set()

    for region in regions:
        client = session.client('sagemaker', region_name=region)
        paginator = client.get_paginator('list_domains')

        for page in paginator.paginate():
            domains = page['Domains']
            for domain in domains:
                domain_name = domain['DomainName']
                domain_arn = domain['DomainArn']

                # Avoid counting global resources multiple times
                if domain_arn not in visited_domains and is_not_aws_managed(domain_name):
                    sagemaker_domains_count += 1
                    visited_domains.add(domain_arn)

    return sagemaker_domains_count

def is_aws_managed(endpoint_name):
    aws_managed_prefixes = ['aws', 'amzn']  # Add other known AWS prefixes if necessary
    return any(endpoint_name.startswith(prefix) for prefix in aws_managed_prefixes)

def aws_sagemaker_endpoint(session, regions):
    total_count = 0
    seen_endpoints = set()
    
    for region in regions:
        sagemaker_client = session.client('sagemaker', region_name=region)
        paginator = sagemaker_client.get_paginator('list_endpoints')
        
        for page in paginator.paginate():
            for endpoint in page['Endpoints']:
                endpoint_name = endpoint['EndpointName']
                
                if not is_aws_managed(endpoint_name) and endpoint_name not in seen_endpoints:
                    seen_endpoints.add(endpoint_name)
                    total_count += 1

    return total_count

def aws_sagemaker_endpoint_configuration(session, regions):
    

    # Initialize a counter for endpoint configurations
    total_endpoint_configurations = 0

    # Iterate over each region provided
    for region in regions:
        # Create a SageMaker client for the specific region
        sagemaker_client = session.client('sagemaker', region_name=region)
        
        # Paginate through the list of endpoint configurations in the region
        paginator = sagemaker_client.get_paginator('list_endpoint_configs')
        page_iterator = paginator.paginate()
        
        # Iterate through each page of results
        for page in page_iterator:
            for endpoint_config in page.get('EndpointConfigs', []):
                # Filter out resources created and managed by AWS
                # Adjust this filter as appropriate for the specifics of your AWS environment and usage
                if not endpoint_config['EndpointConfigName'].startswith('AWS'):
                    total_endpoint_configurations += 1

    # Return the total count of endpoint configurations
    return total_endpoint_configurations

def aws_sagemaker_feature_group(session, regions):
    """
    Count the total number of AWS SageMaker Feature Groups across all specified AWS regions.
    This count excludes any resources that are created and managed by AWS.
    
    :param session: An existing boto3 Session object.
    :param regions: An array of AWS regions.
    :return: Total number of non-AWS managed SageMaker Feature Groups.
    """
    total_feature_groups = 0
    feature_group_names = set()
    
    for region in regions:
        # Create a SageMaker client for the region
        sagemaker_client = session.client('sagemaker', region_name=region)
        
        # Paginate through the list of feature groups
        paginator = sagemaker_client.get_paginator('list_feature_groups')
        for page in paginator.paginate():
            for feature_group in page.get('FeatureGroupSummaries', []):
                feature_group_name = feature_group.get('FeatureGroupName')
                # Skip AWS managed feature groups
                if not feature_group_name.startswith('AWS'):
                    feature_group_names.add(feature_group_name)
                    
    # The unique feature group names (across all regions) would be the final count
    total_feature_groups = len(feature_group_names)
    return total_feature_groups

def aws_sagemaker_notebook_instance(session, regions):
    sagemaker_client = session.client('sagemaker')
    total_notebooks = 0

    for region in regions:
        sagemaker_client = session.client('sagemaker', region_name=region)
        paginator = sagemaker_client.get_paginator('list_notebook_instances')
        for page in paginator.paginate():
            for instance in page['NotebookInstances']:
                if not instance['NotebookInstanceName'].startswith('aws-'):
                    total_notebooks += 1

    return total_notebooks

def aws_sagemaker_studio_lifecycle_config(session, regions):
    

    def is_managed_by_aws(config_name):
        # Add logic to check if the config is managed by AWS
        # Example: return config_name.startswith('aws')
        # This function should be customized based on how AWS managed resources are named
        return config_name.startswith('aws-')  # Assuming AWS managed configs start with 'aws-'

    total_count = 0
    
    for region in regions:
        sagemaker_client = session.client('sagemaker', region_name=region)
        paginator = sagemaker_client.get_paginator('list_studio_lifecycle_configs')
        
        for page in paginator.paginate():
            for config in page['StudioLifecycleConfigs']:
                if not is_managed_by_aws(config['StudioLifecycleConfigName']):
                    total_count += 1

    return total_count

def aws_sagemaker_user_profile(session, regions):
    sagemaker_user_profiles_count = 0
    seen_resources_set = set()

    for region in regions:
        sagemaker_client = session.client('sagemaker', region_name=region)
        paginator = sagemaker_client.get_paginator('list_user_profiles')
        for page in paginator.paginate():
            for user_profile in page['UserProfiles']:
                user_profile_arn = user_profile['UserProfileArn']
                
                # Exclude resources created and managed by AWS
                if 'aws-managed' not in user_profile_arn:
                    # Ensure that global resources are counted only once
                    if user_profile_arn not in seen_resources_set:
                        sagemaker_user_profiles_count += 1
                        seen_resources_set.add(user_profile_arn)

    return sagemaker_user_profiles_count

def aws_sagemaker_workforce(session, regions):
    # Initialize counts
    workforce_count = 0
    unique_workforces = set()

    # Iterate through all the specified regions
    for region in regions:
        # Create a SageMaker client for the current region
        sagemaker_client = session.client('sagemaker', region_name=region)

        # List the workforces in the current region
        paginator = sagemaker_client.get_paginator('list_workforces')
        for page in paginator.paginate():
            for workforce in page['Workforces']:
                # Exclude AWS Managed workforce by checking if it's private
                if workforce['SourceIpConfig']['CidrAllowList']:
                    unique_workforces.add(workforce['WorkforceName'])

    # Once we have iterated through all regions, calculate the total number of unique workforces
    workforce_count = len(unique_workforces)

    return workforce_count

def aws_sagemaker_workteam(session, regions):
    # Initializing Boto3 clients and other variables
    from botocore.exceptions import NoCredentialsError, PartialCredentialsError

    total_count = 0
    seen_workteams = set()
    
    try:
        for region in regions:
            sagemaker_client = session.client('sagemaker', region_name=region)
            # Get the list of workteams in each region
            response = sagemaker_client.list_workteams()

            for workteam in response['Workteams']:
                workteam_name = workteam['WorkteamName']
                if workteam_name not in seen_workteams and not workteam_name.startswith('AWS'):
                    seen_workteams.add(workteam_name)
                    total_count += 1

    except (NoCredentialsError, PartialCredentialsError):
        print("Credentials not available or partially available. Exiting...")
        return

    return total_count

def aws_secretsmanager_secret(session, regions):
    secret_count = 0
    seen_secrets = set()

    for region in regions:
        sm_client = session.client('secretsmanager', region_name=region)
        paginator = sm_client.get_paginator('list_secrets')
        
        for page in paginator.paginate():
            for secret in page.get('SecretList', []):
                if not secret.get('Tags', []):
                    secret_arn = secret.get('ARN')
                    
                    if secret_arn not in seen_secrets:
                        seen_secrets.add(secret_arn)
                        secret_count += 1

    return secret_count

def aws_security_group(session, regions):
    # Initialize a set to hold unique security group IDs to avoid counting duplicates in global resources
    unique_security_groups = set()
    
    # Iterate over all regions
    for region in regions:
        # Create EC2 client for the current region
        ec2_client = session.client('ec2', region_name=region)
        
        # Describe all security groups in the region
        response = ec2_client.describe_security_groups()
        
        for sg in response['SecurityGroups']:
            # Exclude the security groups managed by AWS
            if not sg['GroupName'].startswith('aws-'):
                unique_security_groups.add(sg['GroupId'])
    
    # Return the total count of unique security groups
    return len(unique_security_groups)

def aws_service_discovery_service(session, regions):
    # Initialize count for AWS Service Discovery services
    total_count = 0
    
    # Set to track already counted resources to avoid double counting global resources
    counted_resources = set()
    
    # Iterate through each region
    for region in regions:
        # Create a ServiceDiscovery client for the region
        client = session.client("servicediscovery", region_name=region)
        
        # Initialize next_token for paginated results
        next_token = None
        
        while True:
            # List services with possible pagination using next_token
            if next_token:
                response = client.list_services(NextToken=next_token)
            else:
                response = client.list_services()
            
            # Iterate through services in the response
            for service in response.get("Services", []):
                service_arn = service["Arn"]
                
                # Check if the service is managed by AWS
                if "aws:" not in service_arn:
                    # Check if the service is a global resource
                    if service_arn not in counted_resources:
                        counted_resources.add(service_arn)
                        total_count += 1
                        
            # Check if there is more data to fetch
            next_token = response.get("NextToken")
            if not next_token:
                break
    
    return total_count

def aws_ses_domain_dkim(session, regions):
    """
    Count the total number of aws_ses_domain_dkim across all specified AWS regions, excluding resources
    created and managed by AWS. Global resources are only counted once.
    
    :param session: An existing boto3 session.
    :param regions: A list of AWS regions to scan.
    :return: The total count of aws_ses_domain_dkim.
    """
    seen_domains = set()
    total_dkim_count = 0

    for region in regions:
        ses_client = session.client('ses', region_name=region)
        response = ses_client.list_identities(IdentityType='Domain')

        for domain in response['Identities']:
            if domain not in seen_domains:
                dkim_attributes = ses_client.get_identity_dkim_attributes(Identities=[domain])
                dkim_attributes = dkim_attributes['DkimAttributes']
                
                if domain in dkim_attributes and not dkim_attributes[domain]['DkimEnabled']:
                    total_dkim_count += 1  # Count only user-managed domains
                
                seen_domains.add(domain)

    return total_dkim_count

def aws_ses_domain_identity(session, regions):
    """
    Counts the total number of SES domain identities across all provided regions,
    excluding any resources that are created and managed by AWS.

    Parameters:
    session (boto3.Session): The boto3 session.
    regions (list): List of AWS region codes to be considered.

    Returns:
    int: The total count of SES domain identities.
    """
    total_identity_count = 0
    seen_identities = set()

    for region in regions:
        ses_client = session.client('ses', region_name=region)

        # Paginate through the list of identities
        paginator = ses_client.get_paginator('list_identities')
        response_iterator = paginator.paginate(IdentityType='Domain')

        for response in response_iterator:
            for identity in response.get('Identities', []):
                # Exclude AWS managed resources
                if not identity.endswith('.amazonaws.com'):
                    if identity not in seen_identities:
                        seen_identities.add(identity)
                        total_identity_count += 1

    return total_identity_count

def aws_ses_domain_mail_from(session, regions):
    
    
    def list_mail_from_domains(ses_client):
        try:
            response = ses_client.list_identities(IdentityType='Domain')
            identities = response.get('Identities', [])
            mail_from_domains = []
            for identity in identities:
                mail_from = ses_client.get_identity_mail_from_domain_attributes(
                    Identities=[identity]
                )
                if 'MailFromDomainAttributes' in mail_from:
                    mail_from_domains.append(identity)
            return mail_from_domains
                
        except ClientError as e:
            print(f"An error occurred: {e}")
            return []
    
    global_domains = set()
    total_mail_from_domains = set()
    
    for region in regions:
        ses_client = session.client('ses', region_name=region)
        mail_from_domains = list_mail_from_domains(ses_client)
        for domain in mail_from_domains:
            if domain in global_domains:
                continue
            if domain.startswith('amazonses.com') or domain.endswith('.amazonses.com'):
                continue
            total_mail_from_domains.add(domain)
        global_domains.update(mail_from_domains)
    
    return len(total_mail_from_domains)

def aws_ses_email_identity(session, regions):
    

    counted_identities = set()

    for region in regions:
        client = session.client('ses', region_name=region)
        identities = client.list_identities(IdentityType='EmailAddress')['Identities']

        for identity in identities:
            identity_details = client.get_identity_verification_attributes(Identities=[identity])
            verification_attributes = identity_details['VerificationAttributes'][identity]

            # Skip identities created and managed by AWS
            if verification_attributes['VerificationStatus'] == 'Success' and 'Amazon' not in identity:
                counted_identities.add(identity)

    return len(counted_identities)

def aws_sfn_state_machine(session, regions):
    
    
    # Initialize a counter for the total number of state machines
    total_state_machines = 0
    listed_arns = set()
    
    for region in regions:
        # Create a StepFunctions client for the given region
        sfn_client = session.client('stepfunctions', region_name=region)
        
        try:
            paginator = sfn_client.get_paginator('list_state_machines')
            page_iterator = paginator.paginate()
            
            for page in page_iterator:
                for state_machine in page['stateMachines']:
                    arn = state_machine['stateMachineArn']
                    
                    # Exclude AWS managed resources
                    if not arn.split(":")[5].startswith("aws-"):
                        listed_arns.add(arn)
        
        except Exception as e:
            print(f"An error occurred in region {region}: {str(e)}")
            continue

    # The total number of unique state machines across all regions
    total_state_machines = len(listed_arns)
    
    return total_state_machines

def aws_sns_topic(session, regions):
    sns_counts = {}

    for region in regions:
        # Create SNS client for the current region
        sns_client = session.client('sns', region_name=region)
        
        next_token = None
        region_sns_count = 0
        
        while True:
            if next_token:
                response = sns_client.list_topics(NextToken=next_token)
            else:
                response = sns_client.list_topics()
            
            topics = response.get('Topics', [])
            region_sns_count += len([topic for topic in topics if not topic['TopicArn'].startswith('arn:aws:sns:aws:')])
            
            next_token = response.get('NextToken')
            if not next_token:
                break
        
        sns_counts[region] = region_sns_count
    
    total_sns_count = sum(sns_counts.values())
    return total_sns_count

def aws_sns_topic_subscription(session, regions):
    
    
    # Set to store all unique topic ARNs to ensure global topics are counted only once
    unique_topics = set()

    # Iterate over each region
    for region in regions:
        # Create an SNS client for the specific region
        sns_client = session.client('sns', region_name=region)
        
        # List all topics in the region
        paginator = sns_client.get_paginator('list_topics')
        for page in paginator.paginate():
            for topic in page['Topics']:
                topic_arn = topic['TopicArn']
                unique_topics.add(topic_arn)

    # Filter out AWS-managed resources
    user_managed_topics = [topic for topic in unique_topics if not ":aws:" in topic]

    # Return the count of user-managed SNS topics subscriptions
    return len(user_managed_topics)

def aws_sqs_queue(session, regions):
    sqs_queue_names = set()
    
    for region in regions:
        sqs_client = session.client('sqs', region_name=region)
        response = sqs_client.list_queues()
        
        if 'QueueUrls' in response:
            for queue_url in response['QueueUrls']:
                queue_attributes = sqs_client.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=['All']
                )
                if queue_attributes['Attributes'].get('ManagedBy', '').lower() != 'aws':
                    sqs_queue_names.add(queue_url.split('/')[-1])
    
    return len(sqs_queue_names)

def aws_ssm_parameter(session, regions):
    total_count = 0
    parameter_names = set()  # To avoid counting global parameters multiple times
    
    for region in regions:
        ssm_client = session.client('ssm', region_name=region)
        paginator = ssm_client.get_paginator('describe_parameters')
        
        for page in paginator.paginate():
            for param in page['Parameters']:
                param_name = param['Name']
                if not param_name.startswith('/aws'):
                    parameter_names.add(param_name)
    
    total_count = len(parameter_names)
    return total_count

def aws_subnet(session, regions):
    subnet_count = 0
    
    for region in regions:
        ec2 = session.client('ec2', region_name=region)
        
        # Fetch all subnets in the region
        subnets = ec2.describe_subnets()
        
        for subnet in subnets['Subnets']:
            # Check if the subnet is not managed by AWS
            # We exclude managed subnets by checking the 'Tags' field for the 'aws' key in the Tag's 'Key' field
            if 'Tags' in subnet and not any(tag['Key'].startswith('aws:') for tag in subnet['Tags']):
                subnet_count += 1
            elif 'Tags' not in subnet:
                subnet_count += 1  # Count non-tagged subnets as well

    return subnet_count

def aws_transfer_access(session, regions):
    """
    Count the total number of AWS Transfer Family access across all specified regions,
    excluding any resources created and managed by AWS. Ensure global resources are only
    counted once.
    
    Parameters:
    - session: boto3.session.Session - A boto3 session object
    - regions: list - A list of AWS regions to check
    
    Returns:
    - int - Total count of AWS Transfer Family access points
    """

    transfer_family_clients = {}
    total_count = 0
    global_resources_counted = False

    for region in regions:
        # Create a client for the AWS Transfer Family service
        if region not in transfer_family_clients:
            transfer_family_clients[region] = session.client('transfer', region_name=region)
        
        client = transfer_family_clients[region]

        # List servers (transfer access points)
        paginator = client.get_paginator('list_servers')
        page_iterator = paginator.paginate()
        
        for page in page_iterator:
            for server in page['Servers']:
                if server['IdentityProviderType'] != 'SERVICE_MANAGED':
                    total_count += 1

        if not global_resources_counted:
            # Count global resources
        
            # Assuming a hypothetic function list_global_transfer_resources
            # would be used to count global Transfer Family resources, placed here for example purposes
            
            global_resources = ["ExampleGlobalResource1", "ExampleGlobalResource2"]
            total_count += len(global_resources)
            global_resources_counted = True

    return total_count

def aws_transfer_user(session, regions):
    transfer_users_count = 0
    global_resource_counted = False

    for region in regions:
        # Create a Transfer client for the specific region
        transfer_client = session.client('transfer', region_name=region)
        
        # List all transfer servers
        paginator = transfer_client.get_paginator('list_servers')
        for page in paginator.paginate():
            for server in page.get('Servers', []):
                # Check if the server is a global resource and whether we've already counted global resources
                if server['Arn'].startswith("arn:aws:transfer::") and not global_resource_counted:
                    # List users for global resources
                    user_paginator = transfer_client.get_paginator('list_users')
                    for user_page in user_paginator.paginate(ServerId=server['ServerId']):
                        for user in user_page.get('Users', []):
                            if 'aws-' not in user['UserName']:  # Exclude AWS managed resources
                                transfer_users_count += 1
                    global_resource_counted = True
                elif not server['Arn'].startswith("arn:aws:transfer::"):
                    # List users for regional resources
                    user_paginator = transfer_client.get_paginator('list_users')
                    for user_page in user_paginator.paginate(ServerId=server['ServerId']):
                        for user in user_page.get('Users', []):
                            if 'aws-' not in user['UserName']:  # Exclude AWS managed resources
                                transfer_users_count += 1
    return transfer_users_count

def aws_vpc(session, regions):
    global_vpcs = set()
    total_vpc_count = 0
    
    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        vpcs_response = ec2_client.describe_vpcs()
        
        for vpc in vpcs_response['Vpcs']:
            # Excluding VPCs created and managed by AWS based on the tags or name
            tags = {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])}
            name = tags.get('Name', '').lower()
            if 'aws' not in name:
                vpc_id = vpc['VpcId']
                
                # Since global resources should be counted once, we use a global_vpcs set
                if vpc_id not in global_vpcs:
                    global_vpcs.add(vpc_id)
                    total_vpc_count += 1
    
    return total_vpc_count

def aws_vpc_dhcp_options(session, regions):
    # Create a Boto3 client for EC2 service using the existing session
    def count_dhcp_options_in_region(region):
        ec2_client = session.client("ec2", region_name=region)
        # Fetch all DHCP options in the specified region
        dhcp_options = ec2_client.describe_dhcp_options()
        count = 0
        for option in dhcp_options['DhcpOptions']:
            # Exclude resources managed by AWS (has key 'OwnerId' with AWS ID prefix)
            if not option['DhcpOptionsId'].startswith('dopt-'):
                count += 1
        return count
    
    total_count = 0
    for region in regions:
        total_count += count_dhcp_options_in_region(region)

    return total_count

def aws_vpc_endpoint(session, regions):
    
    
    total_vpc_endpoints = 0
    
    for region in regions:
        try:
            ec2_client = session.client('ec2', region_name=region)
            response = ec2_client.describe_vpc_endpoints()
            
            for vpc_endpoint in response['VpcEndpoints']:
                if 'Tags' in vpc_endpoint:
                    tags = {tag['Key']: tag['Value'] for tag in vpc_endpoint['Tags']}
                    if not (tags.get('aws:cloudformation:stack-name') or tags.get('aws:service')):
                        total_vpc_endpoints += 1
        except ClientError as e:
            print(f"Error accessing region {region}: {e}")

    return total_vpc_endpoints

def aws_vpc_endpoint_service(session, regions):
    

    # Function to count VPC endpoint services in a given region
    def count_vpc_endpoint_services(region):
        client = session.client('ec2', region_name=region)
        response = client.describe_vpc_endpoint_services()
        endpoint_services = response.get('ServiceDetails', [])
        
        # Exclude services created and managed by AWS
        user_managed_services = [
            service for service in endpoint_services 
            if not service.get('Owner') == 'amazon'
        ]
        return len(user_managed_services)

    # Initialize total count
    total_count = 0
    # Keep set for unique global services identifiers to avoid double counting
    global_services = set()

    for region in regions:
        services = count_vpc_endpoint_services(region)
        for service in services:
            if service.get('ServiceType') == 'Interface':
                # Assuming that global services have unique names or IDs we can use to identify
                global_service_id = service.get('ServiceName')
                if global_service_id not in global_services:
                    global_services.add(global_service_id)
                    total_count += 1
            else:
                total_count += 1

    return total_count

def aws_vpc_ipv4_cidr_block_association(session, regions):
    # Initialize the total count of VPC IPv4 CIDR block associations
    total_ipv4_cidr_block_associations = 0

    for region in regions:
        ec2 = session.client('ec2', region_name=region)
        
        # Describe all VPCs in the region
        response = ec2.describe_vpcs()
        
        for vpc in response.get('Vpcs', []):
            # Exclude VPCs that have 'amazon' in their tags, assuming those are managed by AWS
            is_aws_managed = any(
                tag['Key'] == "aws:cloudformation:stack-name" or tag['Key'].startswith("aws:") 
                for tag in vpc.get('Tags', [])
            )
            if not is_aws_managed:
                # Count the associations (primary one is always there, so associations - 1)
                total_ipv4_cidr_block_associations += len(vpc.get('CidrBlockAssociationSet', []))
    
    return total_ipv4_cidr_block_associations

def aws_vpc_ipv6_cidr_block_association(session, regions):
    vpc_association_count = 0
    
    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        
        # Describe VPCs to get IPv6 CIDR block associations
        vpcs = ec2_client.describe_vpcs()
        
        for vpc in vpcs['Vpcs']:
            associations = vpc.get('Ipv6CidrBlockAssociationSet', [])
            for association in associations:
                # Exclude managed associations
                if not association.get('Ipv6CidrBlockState', {}).get('StateMessage', '').startswith('Managed by Amazon'):
                    vpc_association_count += 1
    
    return vpc_association_count

def aws_vpc_peering_connection(session, regions):
    total_peering_connections = 0

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        response = ec2_client.describe_vpc_peering_connections()

        # Filter out AWS managed connections
        managed_peering_connections = [
            connection for connection in response['VpcPeeringConnections']
            if connection['RequesterVpcInfo'].get('OwnerId') == 'amazon-aws' or
               connection['AccepterVpcInfo'].get('OwnerId') == 'amazon-aws'
        ]

        total_peering_connections += (len(response['VpcPeeringConnections']) - len(managed_peering_connections))

    return total_peering_connections

def aws_vpc_peering_connection_accepter(session, regions):
    """
    Count the total number of aws_vpc_peering_connection_accepters across all provided regions.
    
    :param session: An existing boto3 session.
    :param regions: A list of AWS regions to check.
    :return: Total count of aws_vpc_peering_connection_accepters excluding those managed by AWS.
    """
    total_count = 0
    global_resources_checked = set()
    
    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        
        # Retrieve all VPC peering connections in the given region
        response = ec2_client.describe_vpc_peering_connections()
        
        for connection in response['VpcPeeringConnections']:
            # Exclude connections managed by AWS
            if connection.get('AccepterVpcInfo', {}).get('OwnerId') == 'amazon-managed':
                continue
            
            # If global resources (like common IDs) need to be checked once, use a set
            connection_id = connection['VpcPeeringConnectionId']
            if connection_id not in global_resources_checked:
                global_resources_checked.add(connection_id)
                total_count += 1
    
    return total_count

def aws_vpn_connection(session, regions):
    

    total_vpn_connections = 0

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)

        # Describe VPN Connections
        response = ec2_client.describe_vpn_connections()

        for vpn_connection in response.get('VpnConnections', []):
            # Exclude resources created and managed by AWS
            if 'aws' not in vpn_connection['Tags']:
                total_vpn_connections += 1

    return total_vpn_connections

def aws_vpn_gateway(session, region):
    vpn_gateway_count = 0
    for reg in region:
        ec2_client = session.client('ec2', region_name=reg)
        response = ec2_client.describe_vpn_gateways()
        for vpn_gateway in response['VpnGateways']:
            # Exclude VPN gateways that are in "deleted" state and those managed by AWS
            if vpn_gateway['State'] != 'deleted' and not vpn_gateway['Tags']:
                vpn_gateway_count += 1
            else:
                managed_by_aws = False
                for tag in vpn_gateway['Tags']:
                    if tag['Key'].lower() == 'aws managed' and tag['Value'].lower() == 'true':
                        managed_by_aws = True
                        break
                if not managed_by_aws:
                    vpn_gateway_count += 1
    return vpn_gateway_count

def aws_wafv2_web_acl(session, regions):
    # Initialize a set to store unique global WAF ACL IDs
    global_web_acls = set()
    total_count = 0

    for region in regions:
        # Create a WAFv2 client for the given region
        wafv2_client = session.client('wafv2', region_name=region)

        # List Web ACLs in the region
        paginator = wafv2_client.get_paginator('list_web_acls')
        for page in paginator.paginate(Scope='REGIONAL'):
            for web_acl in page['WebACLs']:
                if not web_acl['ManagedByAWS']:
                    total_count += 1
        
        # For the 'GLOBAL' scope, list the Web ACLs only once
        if 'GLOBAL' not in [region.lower() for region in regions]:
            paginator = wafv2_client.get_paginator('list_web_acls')
            for page in paginator.paginate(Scope='CLOUDFRONT'):
                for web_acl in page['WebACLs']:
                    if not web_acl['ManagedByAWS']:
                        if web_acl['ARN'] not in global_web_acls:
                            global_web_acls.add(web_acl['ARN'])
                            total_count += 1

    return total_count

def aws_wafv2_web_acl_logging_configuration(session, regions):
    waf_v2_client_global = session.client('wafv2', region_name='us-east-1')
    global_scope = 'CLOUDFRONT'
    try:
        response = waf_v2_client_global.list_logging_configurations(Scope=global_scope)
        global_logging_configurations = len(response.get('LoggingConfigurations', []))
    except Exception as e:
        global_logging_configurations = 0

    total_logging_configurations = global_logging_configurations

    for region in regions:
        waf_v2_client = session.client('wafv2', region_name=region)
        try:
            paginator = waf_v2_client.get_paginator('list_logging_configurations')
            for page in paginator.paginate(Scope='REGIONAL'):
                logging_configurations = page.get('LoggingConfigurations', [])
                non_aws_managed_configs = [
                    conf for conf in logging_configurations
                    if not conf.get('ManagedByAws', False)
                ]
                total_logging_configurations += len(non_aws_managed_configs)
        except Exception as e:
            # Handle or log exception
            continue

    return total_logging_configurations