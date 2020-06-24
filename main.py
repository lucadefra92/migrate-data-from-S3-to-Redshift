### This file call all the other scripts and executes the project


# Import all the functions
from support_functions import *


# Imprt all the SQL queries
from sql_queries import *

# Define config file path
cfg_file_path = "dl.cfg"

def main(
        new_cluster = True,
        delete_at_end = False
    ):
    """
    Execute the whole project

    Returns
    -------
    None.

    """
    
    cfg_file_path = "dl.cfg"
        
    # Load parameters from config_file
    print("- Loading parameters...")
    # Read parameters from config_file
    access_key_id,          \
    secret_access_key,      \
    role_name,              \
    policy_name,            \
    cluster_identifier,     \
    cluster_type,           \
    node_type,              \
    username,               \
    password,               \
    database_name,          \
    port,                   \
    file_path               \
    = extract_config(cfg_file_path)
    print("- Parameters loaded")
    
    # Create AWS clients and resources
    print("- Creating clients...")
    iam, redshift, ec2 = create_clients(
        access_key_id,
        secret_access_key
    )
    
    print("- Clients created")
        
    if new_cluster:

        
        # Cewate IAM Role
        print("- Creating role...")
        role_arn = create_iam_role(iam, role_name)
        print("- Role created")
        
        # Create IAM Policy and attach it to Role
        print("- Creating policy...")
        create_iam_policy(iam, policy_name, role_name)
        print("- Policy created and attached")
            
        # Create Redshift cluster
        print("- Creating cluster...")
        cluster_endpoint, vpc_security_group_id = create_cluster(
            redshift,
            role_arn,
            cluster_identifier,     
            cluster_type,           
            node_type,              
            username,               
            password,               
            database_name,          
            port
        )
        print("- Cluster created")
    
    else:
        cluster_endpoint = "my-redshift-cluster.clyqsioam55b.us-east-1.redshift.amazonaws.com"
        vpc_security_group_id = "sg-025dee2d"
        role_arn = "arn:aws:iam::341370630698:role/Redshift_access_S3bucket"
    
    
    # Authorize ingress to VPC
    print("- Authorizing ingress to the cluster VPC...")
    authorize_ingress(
        ec2,
        vpc_security_group_id
    )
    print("- Ingress authorized")
    
    # Build connections tring
    conn_string = "postgresql://{}:{}@{}:{}/{}".format(
        username,
        password,
        cluster_endpoint,
        port,
        database_name
    )
    print(cluster_endpoint)
    print(port)
    print(database_name)
    print(conn_string)
    print("- Connection string defined")
    
    print("- Deleting existing table...")
    # Delete table in Redshift cluster
    execute_sql(
        sql_delete_table,
        conn_string,
        False
    )
    print("- Existing table deleted")
    
    print("- Creatiing new table...")
    # Create table in Redshift cluster
    execute_sql(
        sql_create_table,
        conn_string,
        False
    )
    print("- New table created")
    
    print("- Copying data into Redshift...")
    # Copy data from S3 into Redshift cluster
    execute_sql(
        sql_copy_data.format(file_path, role_arn),
        conn_string,
        False
    )
    print("- Data copied into Redshift")
    
    print("- Verifying that data have been copied...")
    # Verify that data have been copied
    execute_sql(
        sql_copy_test,
        conn_string,
        True
    )
    print("- Verification completed")
    
    if delete_at_end:
        delete_cluster(
            redshift,
            cluster_identifier,
            skip_snapshot = True
        )
        
if __name__ == "__main__":
    main(
        new_cluster = False,
        delete_at_end = False
    )

   
    
    
    
    



