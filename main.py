from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from typing import Optional

from api.vt import VirusTotalAPI
from api.ollama import OllamaAPI
from api.logger import vt_logger as logger

app = FastAPI()

# Mount static files 
app.mount("/static", StaticFiles(directory="web"), name="static")

# Setup templates
templates = Jinja2Templates(directory="web")

# Initialize APIs
vt_api = VirusTotalAPI()
ollama_api = OllamaAPI()

class URLAnalysisRequest(BaseModel):
    url: str
    query: Optional[str] = None

class ChatRequest(BaseModel):
    query: str = Field(..., min_length=1, description="The message to send to the chatbot")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/analyze")
async def analyze_url(analysis_request: URLAnalysisRequest):
    try:
        # Get VirusTotal analysis
        vt_analysis = vt_api.get_analysis_summary(analysis_request.url)
        
        # Get AI analysis of the results
        ai_analysis = ollama_api.analyze_phishing(vt_analysis)
        
        # If there's an additional query, process it
        additional_response = None
        if analysis_request.query:
            additional_response = ollama_api.generate_response(
                f"Regarding the URL {analysis_request.url}: {analysis_request.query}"
            )

        system_prompt = """
        Eres un asistente útil especializado en ciberseguridad y detección de phishing. 
        Vas a recibir el análisis de la reputación de una url y debes dar un veredicto. Si hay más de un 10 indicadores de que la url es maliciosa, debes idicar claramente que es maliciosa y que no debe interactuar con ella.
        """
        promt = "¿Es esta URL segura o maliciosa? Resume los puntos clave y da recomendaciones claras."
        
        concise_analysis = ollama_api.generate_response(prompt=promt, system_prompt=system_prompt)
        logger.info("Concise analysis generated successfully")

        return {
            "status": "success",
            "vt_analysis": vt_analysis,
            "ai_analysis": ai_analysis,
            "additional_response": additional_response,
            "concise_analysis": concise_analysis
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/chat")
async def chat(chat_request: ChatRequest):
    try:
        if not chat_request.query.strip():
            raise HTTPException(status_code=400, detail="Query cannot be empty")
        
        system_prompt = """
        You are a helpful assistant specialized in cybersecurity and phishing detection for non tech users. You could find an url reputation analysis in the context.
        """
        url_analysis = ollama_api.latest_analysis if ollama_api.latest_analysis else None
        response = ollama_api.generate_response(chat_request.query, system_prompt=system_prompt, url_analysis=url_analysis)
        return {"status": "success", "response": response}
    except Exception as e:
        logger.error(f"Error in chat: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/clear-context")
async def clear_context():
    ollama_api.clear_context()
    return {"status": "success", "message": "Conversation context cleared"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
