import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler

# Crear el directorio de logs si no existe
log_directory = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
os.makedirs(log_directory, exist_ok=True)

# Configurar el formato de los logs
log_format = logging.Formatter(
    '%(asctime)s [%(levelname)s] %(name)s - %(message)s'
)

def setup_logger(name):
    """
    Configura y devuelve un logger personalizado para cada componente
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Handler para archivo
    # El archivo de log se nombrará con la fecha actual
    today = datetime.now().strftime('%Y-%m-%d')
    file_handler = RotatingFileHandler(
        os.path.join(log_directory, f'{today}_{name}.log'),
        maxBytes=10485760,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(log_format)
    file_handler.setLevel(logging.DEBUG)

    # Handler para consola
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_format)
    console_handler.setLevel(logging.INFO)

    # Añadir handlers al logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

# Crear loggers para cada componente
vt_logger = setup_logger('virustotal')
ollama_logger = setup_logger('ollama')
api_logger = setup_logger('api')