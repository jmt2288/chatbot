class PhishingAnalyzerException(Exception):
    """Base exception for all phishing analyzer exceptions"""
    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class APIKeyError(PhishingAnalyzerException):
    """Raised when there are issues with API keys"""
    def __init__(self, message: str = "API key is missing or invalid"):
        super().__init__(message, status_code=401)

class APIConnectionError(PhishingAnalyzerException):
    """Raised when there are connection issues with external APIs"""
    def __init__(self, service: str, message: str = "Failed to connect to the API"):
        super().__init__(f"{service} API Error: {message}", status_code=503)

class URLAnalysisError(PhishingAnalyzerException):
    """Raised when there are issues analyzing a URL"""
    def __init__(self, message: str = "Failed to analyze URL"):
        super().__init__(message, status_code=400)

class ModelError(PhishingAnalyzerException):
    """Raised when there are issues with the AI model"""
    def __init__(self, message: str = "Error processing with AI model"):
        super().__init__(message, status_code=500)

class ValidationError(PhishingAnalyzerException):
    """Raised when there are validation issues with input data"""
    def __init__(self, message: str = "Invalid input data"):
        super().__init__(message, status_code=422)