import mysql.connector
import uuid
import os
import logging
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger(__name__)


class DatabaseService:
    """Database service for MySQL operations"""


    def __init__(self):
        """Initialize the database service with environment variables"""
        if "DB_HOST" in os.environ:
            self.host = os.environ["DB_HOST"]
            logger.info(f"Using database host '{self.host}' from environment variable 'DB_HOST'")
        else:
            self.host = "localhost"
            logger.warning(f"Using database host '{self.host}' since 'DB_HOST' not set")
        
        if "DB_PORT" in os.environ:
            self.port = int(os.environ["DB_PORT"])
            logger.info(f"Using database port '{self.port}' from environment variable 'DB_PORT'")
        else:
            self.port = 3306
            logger.warning(f"Using database port '{self.port}' since 'DB_PORT' not set")
        
        if "DB_USER" in os.environ:
            self.user = os.environ["DB_USER"]
            logger.info(f"Using database user '{self.user}' from environment variable 'DB_USER'")
        else:
            self.user = "root"
            logger.warning(f"Using database user '{self.user}' since 'DB_USER' not set")
        
        if "DB_PASSWORD" in os.environ:
            self.password = os.environ["DB_PASSWORD"]
            logger.info("Using database password from environment variable 'DB_PASSWORD'")
        else:
            self.password = ""
            logger.warning("Using empty database password since 'DB_PASSWORD' not set")

        logger.info("DatabaseService initialized. Trying to connect to database...")
        try:
            _test_connection = self.create_connection()
            logger.info("Database connection successful")
            _test_connection.close()
        except mysql.connector.errors.ProgrammingError as err:
            logger.info("Database 'auth' does not exist. Creating it...")
            self.execute_init_db_sql()
            logger.info("Database 'auth' created and schema initialized successfully. Trying to connect again...")
            _test_connection = self.create_connection()
            logger.info("Database connection successful")
        


    def execute_init_db_sql(self):
        """Execute the init.sql file to set up the database schema"""
        connection = mysql.connector.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            port=self.port
        )
        try:
            cursor = connection.cursor()
            for statement in init_sql.split(';'):
                if statement.strip():
                    cursor.execute(statement)
            connection.commit()
            logger.info("Database schema updated successfully")
        except mysql.connector.Error as err:
            logger.error(f"Error executing init.sql: {err}")
            raise
        finally:
            cursor.close()
            connection.close()


    def create_connection(self):
        """Creates and returns a connection to the database"""
        return mysql.connector.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database="auth",
            port=self.port
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
        
        cursor = connection.cursor(dictionary=dictionary)
        try:
            cursor.execute(sql, params or ())
            data = cursor.fetchall()
            return data
        except mysql.connector.Error as err:
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
            Last inserted ID for INSERT queries, or number of affected rows
        """
        standalone_connection = False
        if connection is None:
            connection = self.create_connection()
            standalone_connection = True
        
        cursor = connection.cursor()
        try:
            cursor.execute(sql, params or ())
            connection.commit()
            # For INSERT queries, return the last inserted ID
            # For UPDATE/DELETE queries, return the number of affected rows
            return cursor.lastrowid if cursor.lastrowid > 0 else cursor.rowcount
        except mysql.connector.Error as err:
            logger.error("Executing modification query failed!")
            logger.error(f"SQL:   {sql}")
            logger.error(f"Params: {params}")
            logger.error(f"Error: {err}")
            raise
        finally:
            cursor.close()
            if standalone_connection:
                connection.close()


    def generate_uuid(self, table_name: str, max_tries: int = 1000) -> Optional[str]:
        """Generate a unique UUID for a table using secure parameterized queries"""
        connection = self.create_connection()
        try:
            uid = str(uuid.uuid4())
            response = self.execute_query("SELECT id FROM " + table_name + " WHERE id = %s", (uid,), connection=connection)
            tries = 0
            while (response and len(response) > 0 and tries < max_tries):
                uid = str(uuid.uuid4())
                response = self.execute_query("SELECT id FROM " + table_name + " WHERE id = %s", (uid,), connection=connection)
                tries += 1
            
            if tries == max_tries: 
                return None
            return uid
        finally:
            connection.close()

init_sql = """
CREATE DATABASE IF NOT EXISTS `auth`;
USE `auth`;

DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `id` varchar(40) NOT NULL,
  `username` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `premium_level` int DEFAULT '0',
  `stripe_customer_id` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_seen` timestamp NULL DEFAULT NULL,
  `email_verified` tinyint(1) NOT NULL DEFAULT '0',
  `is_admin` tinyint(1) NOT NULL DEFAULT '0',
  `disabled` tinyint(1) NOT NULL DEFAULT '0',
  `hashed_password` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
);

DROP TABLE IF EXISTS `verification_code`;
CREATE TABLE `verification_code` (
  `user_id` varchar(36) NOT NULL,
  `value` varchar(6) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `verified_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`user_id`),
  CONSTRAINT `verification_code_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE
);
"""