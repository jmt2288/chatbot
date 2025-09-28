import requests
from typing import Dict, List, Optional
from .logger import ollama_logger as logger

class OllamaAPI:
    def __init__(self, model: str = "llama2"):
        self.base_url = "http://localhost:11434/api"
        self.model = model
        self.context = []
        self.latest_analysis = None
        
    def generate_response(self, prompt: str, system_prompt: Optional[str] = None, url_analysis: Optional[str] = None) -> str:
        """
        Generate a response using Ollama
        """
        logger.info("Generating response from Ollama")
        headers = {"Content-Type": "application/json"}
        
        # Prepare the messages including system prompt if provided
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        # Add URL analysis context if available
        if url_analysis:
            messages.append({"role": "system", "content": f"Previous URL Analysis:\n{url_analysis}"})
        
        # Add context from previous conversations
        messages.extend(self.context)
        
        # Add the current user message
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = requests.post(
                f"{self.base_url}/chat",
                headers=headers,
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": False
                }
            )
            response.raise_for_status()
            
            result = response.json()
            assistant_message = result.get("message", {}).get("content", "")
            
            # Update context
            self.context.append({"role": "user", "content": prompt})
            self.context.append({"role": "assistant", "content": assistant_message})
            
            # Keep context manageable by limiting to last 10 messages
            if len(self.context) > 10:
                self.context = self.context[-10:]
                
            return assistant_message
            
        except requests.RequestException as e:
            return f"Error generating response: {str(e)}"
    
    def analyze_phishing(self, vt_analysis: Dict) -> str:
        """
        Generate a detailed analysis of potential phishing based on VirusTotal results
        """
        system_prompt = """
        You are a cybersecurity expert specialized in phishing analysis. 
        Analyze the provided VirusTotal scan results and provide:
        1. A clear assessment of the risk level
        2. Detailed explanation of findings
        3. Recommendations for users
        Be concise but thorough in your analysis.
        """
        
        # Create a prompt based on the VirusTotal analysis
        prompt = f"""
        Please analyze these VirusTotal scan results:
        
        Detection Rate: {vt_analysis.get('detection_rate', 'N/A')}
        Total Scans: {vt_analysis.get('total_scans', 'N/A')}
        Positive Detections: {vt_analysis.get('positive_detections', 'N/A')}
        Scan Date: {vt_analysis.get('scan_date', 'N/A')}
        
        Domain Information:
        {vt_analysis.get('domain_info', 'No domain information available')}
        
        Provide a security assessment and recommendations.
        """
        
        response = self.generate_response(prompt, system_prompt)
        self.latest_analysis = response
        return response
    
    def clear_context(self):
        """
        Clear the conversation context and latest analysis
        """
        self.context = []
        self.latest_analysis = None
