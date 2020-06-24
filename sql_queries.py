### This file contains all the SQL queries used in the project


# Delete table called iris if exists
sql_delete_table = """
    DROP TABLE IF EXISTS iris
"""

sql_create_table = """
    CREATE TABLE IF NOT EXISTS iris (
       sepal_length NUMERIC,
       sepal_width NUMERIC,
       petal_length NUMERIC,
       petal_width NUMERIC,
       species VARCHAR
   )
"""

sql_copy_data = """
    COPY iris
    FROM '{}'
    IAM_ROLE '{}' 
    csv
    IGNOREHEADER 1
    ;
"""


sql_copy_test = """
    SELECT *
    FROM iris
    LIMIT 5
"""