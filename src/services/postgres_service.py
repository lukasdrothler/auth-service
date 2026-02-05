import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import os
import logging
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger(__name__)


class PostgresService:
    """Database service for PostgreSQL operations"""


    def __init__(self):
        """Initialize the database service with environment variables"""
        if "POSTGRES_HOST" in os.environ:
            self.host = os.environ["POSTGRES_HOST"]
            logger.info(f"Using database host '{self.host}' from environment variable 'POSTGRES_HOST'")
        else:
            self.host = "localhost"
            logger.warning(f"Using database host '{self.host}' since 'POSTGRES_HOST' not set")
        
        if "POSTGRES_PORT" in os.environ:
            self.port = int(os.environ["POSTGRES_PORT"])
            logger.info(f"Using database port '{self.port}' from environment variable 'POSTGRES_PORT'")
        else:
            self.port = 5432
            logger.warning(f"Using database port '{self.port}' since 'POSTGRES_PORT' not set")
        
        if "POSTGRES_USER" in os.environ:
            self.user = os.environ["POSTGRES_USER"]
            logger.info(f"Using database user '{self.user}' from environment variable 'POSTGRES_USER'")
        else:
            self.user = "root"
            logger.warning(f"Using database user '{self.user}' since 'POSTGRES_USER' not set")
        
        if "POSTGRES_PASSWORD" in os.environ:
            self.password = os.environ["POSTGRES_PASSWORD"]
            logger.info("Using database password from environment variable 'POSTGRES_PASSWORD'")
        else:
            self.password = ""  # nosec
            logger.warning("Using empty database password since 'POSTGRES_PASSWORD' not set")

        if "POSTGRES_DB_NAME" in os.environ:
            self.db_name = os.environ["POSTGRES_DB_NAME"]
            logger.info(f"Using database name '{self.db_name}' from environment variable 'POSTGRES_DB_NAME'")
        else:
            self.db_name = "auth"
            logger.warning(f"Using database name '{self.db_name}' since 'POSTGRES_DB_NAME' not set")

        logger.info("PostgresService initialized. Trying to connect to database...")
        if not self.db_connection_works():
            logger.info(f"Database '{self.db_name}' does not exist. Creating and initializing...")
            self.execute_init_db_sql()
            logger.info(f"Database '{self.db_name}' created and schema initialized successfully.")

        if not self.db_tables_exist():
            logger.info("Database tables do not exist. Initializing schema...")
            self.execute_init_db_sql()
            logger.info("Database schema initialized successfully.")
        
        _test_connection = self.create_connection()
        logger.info("Database connection successful")
        _test_connection.close()


    def db_connection_works(self) -> bool:
        """Check if the database exists"""
        try:
            connection = self.create_connection()
            cursor = connection.cursor()
            cursor.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (self.db_name,))
            exists = cursor.fetchone()
            cursor.close()
            connection.close()
            if exists:
                return True
            return False
        except psycopg2.OperationalError as err:
            logger.warning(f"Error checking if database exists: {err}")
            return False
            


    def db_tables_exist(self) -> bool:
        """Check if the required tables exist in the database"""
        _test_connection = self.create_connection()
        try:
            one_user = self.execute_query('SELECT * FROM "user" LIMIT 1;', connection=_test_connection)
            one_code = self.execute_query("SELECT * FROM verification_code LIMIT 1;", connection=_test_connection)
            if one_user is not None and one_code is not None:
                return True
            return False
        except psycopg2.Error as err:
            logger.warning(f"Error checking if database tables exist: {err}")
            return False
        finally:
            _test_connection.close()
       

    def execute_init_db_sql(self):
        """Execute the init.sql file to set up the database schema"""
        # Step 1: Create Database if it doesn't exist
        connection = self.create_connection(without_db=True)
        connection.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = connection.cursor()
        try:
            # Check if database exists
            cursor.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (self.db_name,))
            exists = cursor.fetchone()
            if not exists:
                logger.info(f"Creating database {self.db_name}")
                cursor.execute(f'CREATE DATABASE "{self.db_name}"')
            else:
                 logger.info(f"Database {self.db_name} already exists")
        except psycopg2.Error as err:
             logger.error(f"Error creating database: {err}")
             raise
        finally:
            cursor.close()
            connection.close()

        # Step 2: Create Tables
        connection = self.create_connection() # Connect to the new DB
        try:
            cursor = connection.cursor()
            for statement in init_sql.split(';'):
                if statement.strip():
                    cursor.execute(statement)
            connection.commit()
            logger.info("Database schema updated successfully")
        except psycopg2.Error as err:
            logger.error(f"Error executing init.sql: {err}")
            raise
        finally:
            cursor.close()
            connection.close()


    def create_connection(self, without_db: bool = False):
        """Creates and returns a connection to the database"""
        if without_db:
            return psycopg2.connect(
                user=self.user, 
                password=self.password,
                host=self.host,
                port=self.port,
                dbname="postgres"
            )
        return psycopg2.connect(
                user=self.user, 
                password=self.password,
                host=self.host,
                port=self.port,
                database=self.db_name
        )
    def execute_query(self, sql: str, params: Optional[Tuple] = None, dictionary: bool = True, connection=None) -> Optional[List[Dict[str, Any]]]:
        """
        Execute a SELECT query with parameterized inputs to prevent SQL injection.
        
        Args:
            sql: SQL query with %s placeholders
            params: Tuple of parameters to bind to the query
            dictionary: Whether to return results as dictionaries
            connection: Optional existing connection to use
            
        Returns:
            List of dictionaries (if dictionary=True) or tuples, or None on error
        """
        standalone_connection = False
        if connection is None:
            connection = self.create_connection()
            standalone_connection = True
        
        cursor = connection.cursor()
        try:
            cursor.execute(sql, params or ())
            
            if dictionary and cursor.description:
                columns = [desc[0] for desc in cursor.description]
                data = [dict(zip(columns, row)) for row in cursor.fetchall()]
                return data
            
            data = cursor.fetchall()
            return data
        except psycopg2.Error as err:
            logger.error("Executing query failed!")
            logger.error(f"SQL:   {sql}")
            logger.error(f"Params: {params}")
            logger.error(f"Error: {err}")
            return None
        finally:
            cursor.close()
            if standalone_connection: 
                connection.close()


    def execute_single_query(self, sql: str, params: Optional[Tuple] = None, connection=None) -> Optional[Dict[str, Any]]:
        """
        Execute a SELECT query that returns a single row with parameterized inputs.
        
        Args:
            sql: SQL query with %s placeholders
            params: Tuple of parameters to bind to the query
            connection: Optional existing connection to use
            
        Returns:
            Dictionary with the first result, or None if no results
        """
        result = self.execute_query(sql, params, dictionary=True, connection=connection)
        if isinstance(result, list) and len(result) > 0:
            return result[0]
        return None


    def execute_modification_query(self, sql: str, params: Optional[Tuple] = None, connection=None) -> Optional[int]:
        """
        Execute an INSERT, UPDATE, or DELETE query with parameterized inputs.
        
        Args:
            sql: SQL query with %s placeholders
            params: Tuple of parameters to bind to the query
            connection: Optional existing connection to use
            
        Returns:
            Number of affected rows
        """
        standalone_connection = False
        if connection is None:
            connection = self.create_connection()
            standalone_connection = True
        
        cursor = connection.cursor()
        try:
            cursor.execute(sql, params or ())
            connection.commit()
            return cursor.rowcount
        except psycopg2.Error as err:
            logger.error("Executing modification query failed!")
            logger.error(f"SQL:   {sql}")
            logger.error(f"Params: {params}")
            logger.error(f"Error: {err}")
            raise
        finally:
            cursor.close()
            if standalone_connection:
                connection.close()


init_sql = """
DROP TABLE IF EXISTS "verification_code";
DROP TABLE IF EXISTS "user";

CREATE TABLE "user" (
  "id" varchar(40) NOT NULL DEFAULT gen_random_uuid()::text,
  "username" varchar(255) NOT NULL,
  "email" varchar(255) NOT NULL,
  "premium_level" int DEFAULT 0,
  "stripe_customer_id" varchar(255) DEFAULT NULL,
  "created_at" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "last_seen" timestamp NULL DEFAULT NULL,
  "email_verified" boolean NOT NULL DEFAULT FALSE,
  "is_admin" boolean NOT NULL DEFAULT FALSE,
  "disabled" boolean NOT NULL DEFAULT FALSE,
  "hashed_password" varchar(255) NOT NULL,
  PRIMARY KEY ("id")
);

CREATE TABLE "verification_code" (
  "user_id" varchar(36) NOT NULL,
  "value" varchar(6) NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "verified_at" timestamp NULL DEFAULT NULL,
  PRIMARY KEY ("user_id"),
  CONSTRAINT "verification_code_fk_1" FOREIGN KEY ("user_id") REFERENCES "user" ("id") ON DELETE CASCADE
);
"""