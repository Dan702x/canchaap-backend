import requests
import os
from dotenv import load_dotenv

# Carga las variables de .env (API_PORT y CRON_SECRET_KEY)
load_dotenv()

API_PORT = os.getenv('API_PORT', 8080)
CRON_SECRET_KEY = os.getenv('CRON_SECRET_KEY')
BASE_URL = f"http://localhost:{API_PORT}"

def run_scheduler_task():
    """
    Simula un Cron Job llamando al endpoint de envío de recordatorios.
    """
    if not CRON_SECRET_KEY:
        print("Error: No se encontró CRON_SECRET_KEY en el archivo .env")
        return

    print("Simulando ejecución del Scheduler (Cron Job)...")
    print("Llamando a la API para enviar recordatorios...")

    try:
        # Preparamos el header de autorización
        headers = {
            'Authorization': f'Bearer {CRON_SECRET_KEY}'
        }
        
        # Llamamos al endpoint
        response = requests.post(f"{BASE_URL}/api/tasks/send-reminders", headers=headers)
        
        if response.status_code == 200:
            print("\n¡Éxito! Tarea completada.")
            print(f"Respuesta del servidor: {response.json().get('mensaje')}")
        else:
            print(f"\nError al ejecutar la tarea. Código de estado: {response.status_code}")
            print(f"Respuesta del servidor: {response.text}")

    except requests.exceptions.ConnectionError:
        print("\nError: No se pudo conectar al backend.")
        print(f"¿Estás seguro de que tu app.py está corriendo en el puerto {API_PORT}?")
    except Exception as e:
        print(f"\nOcurrió un error inesperado: {e}")

if __name__ == "__main__":
    run_scheduler_task()