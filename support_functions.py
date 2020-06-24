### This file contains all the functions called in the main script
# Import packages
import configparser
import boto3
import psycopg2
import json

    
def extract_config(cfg_file_path):
    """
    Extract relevant parameters from cfg_file
    
    Parameters
    ----------
    cfg_file : json file containing relevant parameters.

    Returns
    -------
    access_key_id : str
        AWS Access Key ID.
    secret_access_key : str
        AWS Secret Access Key.
    role_name : str
        IAM Role name.
    policy_name : str
        IAM Policy name.
    cluster_identifier : str
        A unique identifier for the cluster. You use this identifier to refer 
        to the cluster for any subsequent cluster operations such as deleting
        or modifying. 
    cluster_type : str
        The type of the cluster. Valid Values: single-node, multi-node.
    node_type : str
        The node type to be provisioned for the cluster. For information about 
        node types visit Amazon Redshift Cluster Management Guide.
    username : str
        Master username for the Cluster.
    password : str
        The password associated with the master user account for the cluster 
        that is being created.
    database_name : str
        Name for the database created on the cluster.
    port : int
        The port number on which the cluster accepts incoming connections.

    """
    
    # Read config file
    cfg_data = configparser.ConfigParser()
    cfg_data.read('dl.cfg')
     
    # Save AWS credentials
    access_key_id     = cfg_data["AWS"]["access_key_id"]
    secret_access_key = cfg_data["AWS"]["secret_access_key"]
    
    # Save IAM role and IAM policy data
    role_name          = cfg_data["IAM"]["role_name"]
    policy_name        = cfg_data["IAM"]["policy_name"]
    
    # Save Redshift cluster parameters
    cluster_identifier = cfg_data["Redshift"]["cluster_identifier"]
    cluster_type       = cfg_data["Redshift"]["cluster_type"]
    node_type          = cfg_data["Redshift"]["node_type"]
    username           = cfg_data["Redshift"]["username"]
    password           = cfg_data["Redshift"]["password"]
    database_name      = cfg_data["Redshift"]["database_name"]
    port               = int(cfg_data["Redshift"]["port"])
    
    # Save S3 source file path
    file_path = cfg_data["S3"]["file_path"]
    
    return \
        access_key_id,      \
        secret_access_key,  \
        role_name,          \
        policy_name,        \
        cluster_identifier, \
        cluster_type,       \
        node_type,          \
        username,           \
        password,           \
        database_name,      \
        port,               \
        file_path
            
            
def create_clients(
        access_key_id,
        secret_access_key
    ):
    """
    Generate clients and resources for IAM, Redshift, EC2

    Parameters
    ----------
    access_key_id : str
        AWS Access Key ID.
    secret_access_key : str
        AWS Secret Access Key.

    Returns
    -------
    iam : botocore.client.IAM
        A low-level client representing AWS Identity and Access Management.
    redshift : botocore.client.Redshift
        A low-level client representing Amazon Redshift.
    ec2 : botocore.resource.EC2
        A resource representing Amazon Elastic Compute Cloud (EC2).
        
    """
    
    # Create IAM client
    iam = boto3.client(
        "iam",
        region_name = "us-east-1",
        aws_access_key_id = access_key_id,
        aws_secret_access_key = secret_access_key
    )
    
    
    # Create Redshift client
    redshift = boto3.client(
        "redshift",
        region_name = "us-east-1",
        aws_access_key_id = access_key_id,
        aws_secret_access_key = secret_access_key
    )
    
    # Define EC2 resource
    ec2 = boto3.resource(
        "ec2",
        region_name = "us-east-1",
        aws_access_key_id = access_key_id,
        aws_secret_access_key = secret_access_key
    )
    
    return iam, redshift, ec2


    
    
def create_iam_role(
        iam,
        role_name
    ):
    """
    Create IAM role able to use Redshift on behalf of the user, after deleting
    any existing one with the same name

    Parameters
    ----------
    iam : botocore.client.IAM
        A low-level client representing AWS Identity and Access Management.
    role_name : str
        The name of the IAM role to create.

    Returns
    -------
    role_arn : str
        The Amazon Resource Name (ARN) specifying the role.
        
    """
    
    # Try to delete the existing role with the same name, if exists
    try:
        iam.get_role(
            RoleName = role_name
        )
        print("-- Role named {} already exists".format(role_name))
    
        # Extract all the attached policies to the existing role
        attached_policies = iam.list_attached_role_policies(
            RoleName = role_name
        )["AttachedPolicies"]
    
    
        # Iterate over all attached policies
        for attached_policy in attached_policies:
    
            # Extract attached policy ARN
            attached_policy_arn = attached_policy["PolicyArn"]
    
            # Detach policy from role
            iam.detach_role_policy(
                RoleName = role_name,
                PolicyArn = attached_policy_arn
            )
    
        # Delete role
        try:
            iam.delete_role(
                RoleName = role_name
            )
            print("-- Role {} has been deleted".format(role_name))
    
        except Exception as e:
            print(str(e))
            
    except Exception as e:
        print(str(e))
    
    # Create IAM role
    try:
        iam.create_role(
            RoleName = role_name,
            Description = "Allows Redshift cluster to call AWS services on \
                behalf of the user",
            AssumeRolePolicyDocument = json.dumps(
                {
                    "Statement": [
                        {
                            "Action": "sts:AssumeRole",
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "redshift.amazonaws.com"
                            }
                         }
                    ],
                    "Version": "2012-10-17"
                }
            )
        )
        print("-- Role {} has been created".format(role_name))
    
    except Exception as e:
        print(str(e))
     
    # Extract role ARN
    role_arn = iam.get_role(
        RoleName = role_name
    )["Role"]["Arn"]

    return role_arn        



def create_iam_policy(
        iam, policy_name,
        role_name
    ):
    """
    Create IAM policy to access S3 after deleting any existing one with the 
    same name

    Parameters
    ----------
    iam : botocore.client.IAM
        A low-level client representing AWS Identity and Access Management.
    policy_name : str
        Name of the policy document to create.
    role_name : str
        Name of the role to wich to attach the poliicy.

    Returns
    -------
    policy_arn : str
        The Amazon Resource Name (ARN) specifying the policy.
        
    """

    # Check if policy with the wanted name already exists
    try:
        policies = iam.list_policies()["Policies"]
        policy_exists = False
        for policy in policies:
            if policy["PolicyName"] == policy_name:
                existing_policy_arn = policy["Arn"]
                policy_exists = True
                break          
    except:
        None
    
    # If a policy with the same name already exists, delete it
    if policy_exists:
        print("-- Policy {} already exists".format(policy_name))
        
        # Extract all roles
        roles = iam.list_roles()["Roles"]
        
        # Iterate over all the roles
        for role in roles:
            
            # Extract role name
            existing_role_name = role["RoleName"]
            
            # Extract all the attached policy to the role
            attached_policies = iam.list_attached_role_policies(
                RoleName = existing_role_name
            )["AttachedPolicies"]
            
            # Iterate over all the attached policies
            for attached_policy in attached_policies:
    
                # Extract attached policy ARN
                attached_policy_arn = attached_policy["PolicyArn"]
    
                # Checking if the policy correspond to the wanted one
                if attached_policy_arn == existing_policy_arn:
                    
                    # Detach policy from role
                    iam.detach_role_policy(
                        RoleName = existing_role_name,
                        PolicyArn = attached_policy_arn
                    )
                    
                    print("-- Policy with ARN {} detached from role named {}". \
                          format(existing_policy_arn, existing_role_name))
        
        # Extract all the policy versions
        policy_versions = iam.list_policy_versions(
            PolicyArn = existing_policy_arn
        )["Versions"]
        
        # Iterate over all the policy versions
        for policy_version in policy_versions:
            
            # Skip the version if it is a default version
            if policy_version["IsDefaultVersion"]:
                continue
              
            # Extract policy ID
            version_id = policy_version["VersionId"]
            
            # Delete policy version
            iam.delete_policy_version(
                PolicyArn = existing_policy_arn,
                VersionId = version_id
            )
            print("-- Policy with ARN {}, version_ID {} deleted".format(
                existing_policy_arn,
                version_id
                )
            )
        
        # Delete default version of the policy
        iam.delete_policy(
            PolicyArn = existing_policy_arn
        )
        print("-- Policy with ARN {} deleted".format(existing_policy_arn))
        
    else:
        print("-- Policy {} does not exists".format(policy_name))
     
    # Create policy 
    try:
        policy = iam.create_policy(
            PolicyName = policy_name,
            Description = "Allow to list and access content of the target \
                bucket 'data-to-migrate'",
            PolicyDocument = json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "s3:ListBucket"
                            ],
                            "Resource": [
                                "arn:aws:s3:::data-to-migrate"
                            ]
                        },
                        {
                            "Effect": "Allow",
                            "Action": [
                                "s3:PutObject",
                                "s3:GetObject",
                                "s3:DeleteObject"
                            ],
                            "Resource": [
                                "arn:aws:s3:::data-to-migrate/*"
                            ]
                        }
                    ]
                }
            )
        )
        print("-- Policy named {} created".format(policy_name))
        policy_arn = policy["Policy"]["Arn"]
        print("-- Policy has ARN: {}".format(policy_arn))
    except Exception as e:
        print(str(e))
    
    # Attach policy to IAM role
    try:
        iam.attach_role_policy(
            RoleName = role_name,
            PolicyArn = policy_arn
        )
        print("-- Policy named {} attached to role {}".format(
            policy_name,
            role_name
            )
        )
    except Exception as e:
        print(str(e))
        
    return policy_arn



def delete_cluster(
        redshift,
        cluster_identifier,
        skip_snapshot = True
    ):
    """
    Delete Redshift cluster if exists

    Parameters
    ----------
    redshift : botocore.client.Redshift
        A low-level client representing Amazon Redshift.    
    cluster_identifier : str
        A unique identifier for the cluster. You use this identifier to refer 
        to the cluster for any subsequent cluster operations such as deleting
        or modifying.
    skip_snapshot : bool, optional
        Select if to take a snapshot before deleting the cluster. The default
        is True.

    Returns
    -------
    None

    """
    
    try:
        # Delete Cluster
        redshift.delete_cluster(
            ClusterIdentifier = cluster_identifier,
            SkipFinalClusterSnapshot = skip_snapshot,
        )
        
        print("-- A cluster named {} already exists".format(cluster_identifier))
        print("-- Deleting existing cluster named {}...".format(cluster_identifier))

        
        # Wait for the cluster status change to deleted
        delete_waiter = redshift.get_waiter("cluster_deleted")
        delete_waiter.wait(
            ClusterIdentifier = cluster_identifier,
            WaiterConfig = {
                "Delay": 30,
                "MaxAttempts": 20
            }
        )
        
        print("-- Existing cluster named {} deleted".format(cluster_identifier))
        
    except:
        print("-- A cluster named {} does not exist".format(cluster_identifier))  
    
    return None



def create_cluster(
        redshift,
        role_arn,
        cluster_identifier,     
        cluster_type,           
        node_type,              
        username,               
        password,               
        database_name,          
        port 
    ):
    """
    Create Redshift cluster, after deleting any existing one with the same 
    name

    Parameters
    ----------
    redshift : botocore.client.Redshift
        A low-level client representing Amazon Redshift.
    role_arn : str
        The Amazon Resource Name (ARN) specifying the role.
    cluster_identifier : str
        A unique identifier for the cluster. You use this identifier to refer 
        to the cluster for any subsequent cluster operations such as deleting
        or modifying.
    cluster_type : str
        The type of the cluster. Valid Values: single-node, multi-node.
    node_type : str
        The node type to be provisioned for the cluster. For information about 
        node types visit Amazon Redshift Cluster Management Guide.
    username : str
        Master username for the Cluster.
    password : str
        The password associated with the master user account for the cluster 
        that is being created.        
    database_name : str
        Name for the database created on the cluster.
    port : int
        The port number on which the cluster accepts incoming connections.

    Returns
    -------
    cluster_endpoint : str 
        The connection endpoint.
    cluster_vpc_id : str
        The identifier of the VPC the cluster is in, if the cluster is in a VPC.
    vpc_security_group_id : str
        The identifier of the VPC Security Group.
        
    """  

    # Delete Redshift cluster with the same name if it exists
    delete_cluster(
        redshift,
        cluster_identifier,
        True
    )
    
    # Create Redshift cluster
    try:
        redshift.create_cluster(
            DBName = database_name,
            ClusterIdentifier = cluster_identifier,
            ClusterType = cluster_type,
            NodeType = node_type,
            MasterUsername = username, 
            MasterUserPassword = password, 
            Port = port,
            IamRoles = [role_arn]
        )
        
    except Exception as e:
        print(e)

    print("-- Creating new cluster...")
    
    # Wait for the new cluster status change to available
    create_waiter = redshift.get_waiter("cluster_available")
    create_waiter.wait(
            ClusterIdentifier = cluster_identifier,
            WaiterConfig = {
                "Delay": 30,
                "MaxAttempts": 20
            }
        )
    
    print("-- New cluster created")
    
    # Extract cluster info
    clusters = redshift.describe_clusters(
            ClusterIdentifier = cluster_identifier
        )["Clusters"]
    
    for cluster in clusters:
        if cluster["ClusterIdentifier"] ==  cluster_identifier:
            break

    cluster_endpoint = cluster["Endpoint"]["Address"]
    vpc_security_group_id = cluster["VpcSecurityGroups"][0]["VpcSecurityGroupsId"]

    return cluster_endpoint, vpc_security_group_id


def authorize_ingress(
        ec2,
        vpc_security_group_id
    ):
    """
    Adds the specified ingress rules to a security group.

    Parameters
    ----------
    ec2 : boto3.resources.factory.ec2.ServiceResource
        A resource representing Amazon Elastic Compute Cloud (EC2).
    cluster_vpc_id : str
        The identifier of the VPC the cluster is in, if the cluster is in a VPC.
    vpc_security_group_id : str
        The identifier of the VPC Security Group.

    Returns
    -------
    None
    
    """
    
    
    try:  
        # Extract security group for the VPC
        vpc_sg = ec2.SecurityGroup(id = vpc_security_group_id)
        
        # Authorize ingress connection into the VPC
        vpc_sg.authorize_ingress(
            GroupName = vpc_sg.group_name,
            CidrIp = "0.0.0.0/0",
            IpProtocol = "TCP",
            FromPort = 5439,
            ToPort = 5439
        )
        
    except Exception as e:
    
        # Check if the error is a duplication error
        if "InvalidPermission.Duplicate" in str(e):
            print("-- Rule requested already exists")
        else:
            print("-- {}".format(str(e)))

    return None




def execute_sql(
        sql_query,
        conn_string,
        print_results = False
    ):
    """
    Execute a SQL query on the database associated with a connection string

    Parameters
    ----------
    sql_query : str
        SQL query to execute.
    conn_string : str
        Postgres connection string, of the type: 
        "postgresql://{username}:{password}@{endpoint}:{port}/{DB_name}
    print_results : bool, optional
        DESCRIPTION. Select if to print the results of the query. The default 
        is False.

    Returns
    -------
    None.

    """
    
    # Connect to the database
    conn = psycopg2.connect(conn_string)
    
    # Define cursor
    cur = conn.cursor()
    
    # Execute query
    cur.execute(sql_query)
    conn.commit()
    
    if print_results:
        print(cur.fetchall())
    
    # Close cursor
    cur.close()
    
    # Close connection
    conn.close()
    
    return None




    
    
    




