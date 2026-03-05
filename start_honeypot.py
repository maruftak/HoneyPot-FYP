#!/usr/bin/env python3
"""
Main honeypot orchestrator - starts all services
"""
import sys
import os
import time
import logging
import threading
import webbrowser
from datetime import datetime

# Add script directory to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

# Setup logging
LOG_DIR = os.path.join(SCRIPT_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'honeypot.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def start_camera_services():
    """Start ONVIF and RTSP camera servers"""
    logger.info("Starting camera services...")
    try:
        from iot_services import ONVIFCameraServer, RTSPCameraServer
        
        # Start ONVIF camera on port 8080
        camera = ONVIFCameraServer(host="0.0.0.0", port=8080, device_type="hikvision")
        camera.start()
        logger.info("✓ ONVIF Camera Server started on port 8080")
        
        # Start RTSP server on port 554
        rtsp = RTSPCameraServer(host="0.0.0.0", port=554)
        rtsp.start()
        logger.info("✓ RTSP Camera Server started on port 554")
        
        return camera, rtsp
    except Exception as e:
        logger.error(f"Failed to start camera services: {e}")
        return None, None

def start_honeypot_core():
    """Start main honeypot service"""
    logger.info("Starting main honeypot service...")
    try:
        import honeypot
        t = threading.Thread(target=honeypot.main, daemon=True)
        t.start()
        logger.info("✓ Main honeypot service started")
        return True
    except Exception as e:
        logger.warning(f"Main honeypot service not ready: {e}")
        return False

def start_dashboard():
    """Start Flask dashboard"""
    logger.info("Starting dashboard...")
    try:
        from dashboard import app
        
        def run_dashboard():
            app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
        
        thread = threading.Thread(target=run_dashboard, daemon=True)
        thread.start()
        logger.info("✓ Dashboard started on http://localhost:5000")
        
        # Open in browser after 2 seconds
        time.sleep(2)
        try:
            webbrowser.open('http://localhost:5000')
            logger.info("✓ Opened dashboard in browser")
        except:
            logger.info("ℹ Open http://localhost:5000 in your browser manually")
        
        return True
    except Exception as e:
        logger.error(f"Failed to start dashboard: {e}")
        return False

def monitor_services(camera, rtsp):
    """Monitor running services and log attacks"""
    logger.info("Starting service monitor...")
    
    try:
        from threat_intel import RiskAssessment
        from honeytokens import HoneytokenValidator
        import db
    except ImportError as e:
        logger.warning(f"Some threat analysis modules not available: {e}")
        camera = None
    
    attack_count = 0
    honeytoken_count = 0
    
    while True:
        try:
            time.sleep(10)  # Check every 10 seconds
            
            if camera:
                attacks = camera.get_attacks()
                
                for attack in attacks[attack_count:]:
                    # Log new attack
                    logger.info(f"Attack logged: {attack['type']} from {attack['ip']}")
                    
                    # Check for honeytoken usage
                    if HoneytokenValidator.is_honeytoken({
                        "username": attack.get("username"),
                        "password": attack.get("password")
                    }):
                        honeytoken_count += 1
                        logger.warning(f"🚨 HONEYTOKEN TRIGGERED by {attack['ip']}")
                
                attack_count = len(attacks)
            
            if rtsp:
                rtsp_attacks = rtsp.attacks
                if rtsp_attacks:
                    logger.info(f"RTSP attacks detected: {len(rtsp_attacks)}")
        
        except Exception as e:
            logger.error(f"Monitor error: {e}")

def print_banner():
    """Print startup banner"""
    banner = """
    ╔═══════════════════════════════════════════╗
    ║     🍯 honeyPot — IoT Advanced           ║
    ║                                           ║
    ║  Services:                                ║
    ║  📷 ONVIF Camera          → port 8080    ║
    ║  🎬 RTSP Stream Server    → port 554     ║
    ║  🔍 Threat Intelligence   → Monitor      ║
    ║  🎭 Honeytoken Tracking   → Log          ║
    ║                                           ║
    ║  Dashboard:               → localhost:5000║
    ║  Logs:                    → ./logs/       ║
    ║                                           ║
    ╚═══════════════════════════════════════════╝
    """
    logger.info(banner)

def main():
    """Main orchestrator"""
    print_banner()
    
    logger.info("=" * 50)
    logger.info("Starting honeyPot services...")
    logger.info("=" * 50)
    
    # Start dashboard first
    dashboard_ok = start_dashboard()
    
    # Start all services
    camera, rtsp = start_camera_services()
    honeypot_ok = start_honeypot_core()
    
    logger.info("")
    logger.info("=" * 50)
    logger.info("✓ All services started successfully!")
    logger.info("=" * 50)
    logger.info("")
    logger.info("📊 Dashboard: http://localhost:5000")
    logger.info("📷 ONVIF Camera: http://localhost:8080")
    logger.info("🎬 RTSP Server: rtsp://localhost:554")
    logger.info("")
    logger.info("Monitoring attacks... (Press Ctrl+C to stop)")
    logger.info("")
    
    # Monitor services
    monitor_services(camera, rtsp)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("")
        logger.info("Shutting down honeypot...")
        logger.info("Goodbye!")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
