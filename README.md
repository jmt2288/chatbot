# Phishing Analyzer

Esta aplicación web permite analizar URLs en busca de posibles amenazas de phishing utilizando la API de VirusTotal y un modelo de IA local (Ollama) para proporcionar análisis detallados y recomendaciones.

## Requisitos Previos

- Python 3.8 o superior
- [Ollama](https://ollama.ai/) instalado y ejecutándose localmente
- Una clave de API de VirusTotal

## Instalación

1. Clona este repositorio:
```bash
git clone <url-del-repositorio>
cd phishing-analyzer/app
```

2. Crea un entorno virtual y actívalo:
```bash
python -m venv venv
# En Windows
.\venv\Scripts\activate
# En Unix o MacOS
source venv/bin/activate
```

3. Instala las dependencias:
```bash
pip install -r requirements.txt
```

4. Añade tu api de virustotal en el fichero 'vt.py'
```
self.api_key = "<your_virustotal_api_key_here>" 
```

## Configuración

1. Asegúrate de que Ollama está instalado y ejecutándose en tu sistema
2. Por defecto, la aplicación usa el modelo "llama2". Puedes modificar el modelo en `api/ollama.py`
3. El servidor de Ollama debe estar ejecutándose en `http://localhost:11434`

## Uso

1. Inicia el servidor:
```bash
python main.py
```

2. Abre tu navegador y ve a `http://localhost:8000`

3. Introduce una URL para analizarla

La aplicación proporcionará:
- Análisis de reputación de VirusTotal
- Análisis de IA sobre la potencial amenaza de phishing
- Capacidad de hacer preguntas adicionales sobre los resultados

## Características

- Análisis de URLs mediante VirusTotal
- Análisis de dominio para URLs sospechosas
- Integración con IA local para análisis detallado
- Interfaz web intuitiva
- Chat interactivo para consultas adicionales

## Estructura del Proyecto

```
app/
├── api/
│   ├── exceptions.py
│   ├── logger.py
│   ├── ollama.py
│   └── vt.py
├── web/
│   ├── index.html
│   └── style.css
├── logs/
├── main.py
└── requirements.txt
```

## Seguridad

- Asegúrate de mantener tu clave API de VirusTotal segura
- No compartas tus archivos logs
- La aplicación está diseñada para uso local/desarrollo

## Contribuir

Si deseas contribuir a este proyecto:

1. Haz un Fork del repositorio
2. Crea una rama para tu función (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## Licencia

Ver el archivo `LICENSE` para más detalles.
