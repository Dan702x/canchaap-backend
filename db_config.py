import os
import mysql.connector
from dotenv import load_dotenv

load_dotenv()

def get_db_connection():
    try:
        # Configuración básica
        config = {
            'host': os.getenv('DB_HOST'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD'),
            'database': os.getenv('DB_NAME'),
            'port': int(os.getenv('DB_PORT', 3306)) # Aseguramos el puerto
        }

        # --- ¡AQUÍ ESTÁ LA MAGIA DEL SSL! ---
        # Aiven requiere esto obligatoriamente
        config['ssl_ca'] = 'ca.pem' 
        config['ssl_disabled'] = False
        # ------------------------------------

        conn = mysql.connector.connect(**config)
        return conn
    except mysql.connector.Error as err:
        print(f"Error al conectar a la base de datos: {err}")
        return None