# Migrate Data from S3 to Redshift

*Created by: Luca De Francesco*

## Introduction

This project consists of a step-by-step tutorial describing how to migrate data stored in S3 to AWS Redshift. S3, the cloud storage service by AWS, allows storing files in an effcient and cost effective way. On the other hand, Redshift is the Data Warehouse solution proposed by Amazon; this is based on Postgres SQL.

A common scenario consists of migrating data stored in files on S3 to Redshift. This is quite a common need in corporate environments, since Redshift is a more practical tool for for business analysis. In this project, we will focus on the steps of programmatically creating a Redshift cluster. The data to be transferred is a very simple CSV file, but this can easily be replaced with more complex data source.

In order to make the steps more easily replicable and automatized, all the steps will be executed using AWS SDK for Python, called Boto3; this provides APIs allowing to control the AWS environment using Python.

The project can be easily replicated by the user, provided the following prerequisited are satisfied:
- The user has an AWS account and owns AWS credentials for programmatic access (AWS Access Key Id and AWS Secret Access Key).
- The user has Python and Boto3 installed on his own machine or on a virtual machine.


## Pipeline description


In order to reach the goal, a pipeline composed of the following steps has been designed:
- Create an Identity Access Management (IAM) role, which allow a specific AWS service to call other services on behalf of the user. In this case, we will assign the role to Redshift as we need it to read data from a secondary service (S3). The user can define the name for the role that will be created. Since it is not possible to have more than one role with the same name, the code will check that no other role named the same way already exists and, if it does, it will delete it before creating the new role.
- Create an IAM policy and attach it to the role. The policy will grant the role the permission to read data from S3. Also in this case, the user can define the name of the policy. If a policy with the same name already exists, this will be deleted before creating a new one.
- Create Redshift cluster. In this case, the user will be able to define several cluster parameters (cluster identifier, cluster type, node type, database name, etc.). Similarly to what done for the role and the policy, the code will check that no other cluster with the same identifier already exists and, in case it does, deletes it before creating the new one. 
- Create a table (with the proper structure) in the database running on the cluster. The table will host the data copied from the file in S3.
- Copy data from the file in S3 to the Redshift cluster.
- Optional: delete the cluster.

All the user-defined parameters will be read from a .cfg file named \texttt{}. The congif file is structuted according to sections (AWS, Redshift, S3, ...), where each section contains parameters related to a logical domain.

## Content of the Github Repository

This repository contains the following files:
- pipeline.ipynb: this Jupyter notebook proposed and execute the pipeline according to a didactic approach; Python packages are loaded when they are needed (so that the user can easily understand for which scope they are used) and each code snippet is well-described with text cells.
- main.py: this Python file is structured according to logical subroutines (one subroutine for each step of the pipeline). All of them are called by the main() function. In particular, all the subroutines are saved in the external file 'support_functions.py'; similarly, all the SQL queries executed on the data warehouse are stored in the external file 'sql_queries.py'.
- support_functions.py: contains all the subroutines functions used by main.py.
- sql_queries.py: contains all the SQL queries executed on the data warehouse by main.py.

Also, please notice that a post describing this project has been published on Medium. This can be found at: https://medium.com/@lucadefra92/stage-data-from-s3-to-redshift-a6c8f80e3b7.

