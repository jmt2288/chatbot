import os
import requests
from typing import Dict, Optional
from dotenv import load_dotenv
from .logger import vt_logger as logger

load_dotenv()

class VirusTotalAPI:
    def __init__(self):
        logger.info("Initializing VirusTotal API")
        #self.api_key = os.getenv("VT_API_KEY")
        self.api_key = "<your_virustotal_api_key_here>"  # Replace with your actual API key https://www.virustotal.com/
        if not self.api_key:
            logger.error("VirusTotal API key not found in environment variables")
            raise ValueError("VirusTotal API key not found in environment variables")
        self.base_url = "https://www.virustotal.com/api/v3"
        logger.info("VirusTotal API initialized successfully")

    def analyze_url(self, url: str) -> Dict:
        """
        Analyze a URL using VirusTotal API
        """
        logger.info(f"Starting URL analysis for: {url}")
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        logger.debug("Headers configured for request")

        try:
            # Submit the URL for scanning
            logger.debug(f"Submitting URL for scanning: {url}")
            scan_response = requests.post(
                f"{self.base_url}/urls",
                headers=headers,
                data={"url": url}
            )
            scan_response.raise_for_status()
            
            # Extract scan_id
            scan_data = scan_response.json()
            logger.debug(f"Scan submission response: {scan_data}")
            
            raw_id = scan_data.get("data", {}).get("id", "")
            if not raw_id:
                raise ValueError("No analysis ID received from VirusTotal")
                
            id = raw_id.split('-')[1] if raw_id.startswith('u-') and '-' in raw_id else raw_id
            logger.debug(f"Analysis ID obtained: {id}")

            # Get the report
            logger.debug("Retrieving analysis report")
            report_response = requests.get(
                f"{self.base_url}/urls/{id}",
                headers=headers
            )
            report_response.raise_for_status()
            
            report_data = report_response.json()
            logger.debug("Analysis report retrieved successfully")
            return report_data

        except requests.exceptions.RequestException as e:
            error_msg = f"Error during URL analysis: {str(e)}"
            logger.error(error_msg)
            raise ValueError(error_msg)

    def get_domain_report(self, domain: str) -> Dict:
        """
        Get a domain report from VirusTotal
        """
        logger.info(f"Getting domain report for: {domain}")
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        
        try:
            response = requests.get(
                f"{self.base_url}/domains/{domain}",
                headers=headers
            )
            response.raise_for_status()
            
            report_data = response.json()
            logger.debug("Domain report retrieved successfully")
            return report_data
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Error getting domain report: {str(e)}"
            logger.error(error_msg)
            raise ValueError(error_msg)

    def analyze_report(self, report: Dict) -> Dict:
        """
        Analyze a VirusTotal report and return a summary
        """
        logger.debug("Starting report analysis")
        try:
            # Verificar la estructura del reporte
            if not isinstance(report, dict) or "data" not in report:
                logger.error("Invalid report format received")
                return {
                    "status": "error",
                    "message": "Invalid report format from VirusTotal"
                }

            # Obtener los atributos del análisis
            attributes = report["data"]["attributes"]
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            last_analysis_results = attributes.get("last_analysis_results", {})
            
            # Calcular estadísticas
            total_engines = sum(last_analysis_stats.values())
            malicious = last_analysis_stats.get("malicious", 0)
            suspicious = last_analysis_stats.get("suspicious", 0)
            positives = malicious + suspicious
            
            logger.debug(f"Analysis stats - Total: {total_engines}, Malicious: {malicious}, Suspicious: {suspicious}")

            result = {
                "status": "success",
                "total_scans": total_engines,
                "positive_detections": positives,
                "detection_rate": f"{(positives/total_engines)*100:.1f}%" if total_engines > 0 else "0%",
                "scan_date": attributes.get("last_analysis_date", "N/A"),
                "reputation": attributes.get("reputation", 0),
                "threat_categories": attributes.get("categories", []),
                "detailed_results": last_analysis_results
            }

            logger.info(f"Report analysis completed successfully. Detection rate: {result['detection_rate']}")
            return result

        except KeyError as e:
            error_msg = f"Missing required field in report: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg
            }
        except Exception as e:
            error_msg = f"Error analyzing report: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg
            }

    def get_analysis_summary(self, url: str) -> Dict:
        """
        Get a complete analysis summary for a URL
        """
        logger.info(f"Getting complete analysis summary for URL: {url}")
        try:
            # Analizar URL
            report = self.analyze_url(url)
            logger.debug("URL analysis completed")
            
            # Analizar reporte
            analysis = self.analyze_report(report)
            logger.debug("Report analysis completed")
            
            # Si es un dominio, obtener información adicional
            if "." in url and "/" not in url:
                try:
                    logger.debug(f"Getting additional domain information for: {url}")
                    domain_report = self.get_domain_report(url)
                    domain_data = domain_report.get("data", {})
                    
                    if domain_data:
                        analysis["domain_info"] = {
                            "categories": domain_data.get("attributes", {}).get("categories", {}),
                            "creation_date": domain_data.get("attributes", {}).get("creation_date", "N/A"),
                            "last_update_date": domain_data.get("attributes", {}).get("last_update_date", "N/A"),
                            "registrar": domain_data.get("attributes", {}).get("registrar", "N/A"),
                            "reputation": domain_data.get("attributes", {}).get("reputation", 0)
                        }
                        logger.debug("Domain information added to analysis")
                except Exception as domain_error:
                    logger.warning(f"Error getting domain information: {str(domain_error)}")
                    analysis["domain_info_error"] = str(domain_error)
            
            logger.info("Analysis summary completed successfully")
            return analysis
            
        except Exception as e:
            error_msg = f"Error analyzing URL: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg
            }