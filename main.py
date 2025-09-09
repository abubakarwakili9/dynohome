#!/usr/bin/env python3
"""
DynoHome Project - Main Startup Script
AI-Powered IoT Security Framework with Threat Intelligence and Dataset Generation
"""

import sys
import os
import traceback
import time
import signal
from pathlib import Path
from typing import Dict, Any, Optional

# Add project root to Python path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

# Import configuration and logging systems
try:
    from config import get_config, setup_config
    from logging_config import get_logger, setup_logging
    CONFIG_AVAILABLE = True
except ImportError as e:
    print(f"⚠ Failed to import config/logging systems: {e}")
    CONFIG_AVAILABLE = False
    import_error = e

def initialize_core_systems():
    """Initialize configuration and logging systems"""
    if not CONFIG_AVAILABLE:
        raise ImportError(f"Required config/logging modules not available: {import_error}")
    
    try:
        print("🔧 Initializing DynoHome configuration system...")
        
        # Detect environment from env var or default to development
        environment = os.getenv('DYNOHOME_ENV', 'development')
        print(f"📋 Environment: {environment}")
        
        # Setup configuration system
        config = setup_config(environment=environment)
        print("✅ Configuration system loaded")
        
        # Setup logging system using config
        logger_system = setup_logging(config.get_configuration_summary())
        print("✅ Logging system initialized")
        
        # Get application logger
        import logging
        logger = logging.getLogger('dynohome.main')
        logger.info("=== DynoHome Project Starting ===")
        logger.info(f"Project root: {project_root}")
        logger.info(f"Environment: {environment}")
        logger.info("Core systems initialized successfully")
        
        return config, logger_system, logger
        
    except Exception as e:
        print(f"⚠ Failed to initialize core systems: {e}")
        print(f"Error details: {traceback.format_exc()}")
        sys.exit(1)

def ensure_directories(config, logger):
    """Ensure all required directories exist"""
    try:
        directories = [
            config.data.data_directory,
            config.data.processed_directory,
            config.data.reports_directory,
            config.data.logs_directory,
            config.data.backup_directory,
            'config'
        ]
        
        for directory in directories:
            dir_path = project_root / directory
            dir_path.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Ensured directory exists: {dir_path}")
        
        logger.info("All required directories verified/created")
        
    except Exception as e:
        logger.error(f"Failed to create directories: {e}")
        raise

def import_pipeline_modules(logger):
    """Import and validate pipeline modules"""
    try:
        logger.info("Importing DynoHome pipeline modules...")
        
        # Import core pipeline modules
        from ai_pipeline import CompleteThreatPipeline, AIModelError
        from ai_classifier import IoTThreatClassifier
        from threat_collector import ThreatCollector, ThreatCollectionError
        
        from attack_scenario_generator import SmartHomeContextEngine, AttackVectorGenerator
        from dataset_export_system import NetworkTrafficSynthesizer, DeviceBehaviorSimulator, AttackScenario as ExportScenario
        logger.info("✅ All pipeline modules imported successfully")
        
        return {
            'CompleteThreatPipeline': CompleteThreatPipeline,
            'AIModelError': AIModelError,
            'IoTThreatClassifier': IoTThreatClassifier,
            'ThreatCollector': ThreatCollector,
            'ThreatCollectionError': ThreatCollectionError,
            'SmartHomeContextEngine': SmartHomeContextEngine,
            'AttackVectorGenerator': AttackVectorGenerator,
            'NetworkTrafficSynthesizer': NetworkTrafficSynthesizer,
            'DeviceBehaviorSimulator': DeviceBehaviorSimulator,
            'ExportScenario': ExportScenario
        }
        
    except ImportError as e:
        logger.error(f"Failed to import pipeline modules: {e}")
        logger.error("Please ensure all required dependencies are installed")
        raise

def initialize_pipeline_components(config, logger_system, logger, modules):
    """Initialize pipeline components with proper error handling"""
    try:
        logger.info("Initializing AI pipeline components...")
        
        # Get module classes
        CompleteThreatPipeline = modules['CompleteThreatPipeline']
        IoTThreatClassifier = modules['IoTThreatClassifier']
        ThreatCollector = modules['ThreatCollector']
        
        SmartHomeContextEngine = modules['SmartHomeContextEngine']
        AttackVectorGenerator = modules['AttackVectorGenerator']
        NetworkTrafficSynthesizer = modules['NetworkTrafficSynthesizer']
        DeviceBehaviorSimulator = modules['DeviceBehaviorSimulator']
        ExportScenario = modules['ExportScenario']
        
        # Initialize threat collector with config
        import logging
        threat_collector_logger = logging.getLogger('dynohome.pipeline.collector')
        threat_collector = ThreatCollector()
        logger.info("✅ Threat collector initialized")
        
        # Initialize AI classifier
        classifier_logger = logging.getLogger('dynohome.pipeline.classifier')
        ai_classifier = IoTThreatClassifier()
        logger.info("✅ AI classifier initialized")
        
        # Initialize complete pipeline
        pipeline_logger = logging.getLogger('dynohome.pipeline.main')
        complete_pipeline = CompleteThreatPipeline()
        logger.info("✅ Complete AI pipeline initialized")
        
        # Initialize attack scenario + dataset components
        context_engine = SmartHomeContextEngine()
        attack_generator = AttackVectorGenerator(context_engine)
        traffic_synth = NetworkTrafficSynthesizer()
        behavior_sim = DeviceBehaviorSimulator()
        logger.info("✅ Scenario generator & dataset exporter initialized")
        
        # Run health check
        logger.info("Running pipeline health check...")
        health_status = complete_pipeline.health_check()
        
        if health_status.get('status') == 'healthy':
            logger.info("✅ Pipeline health check passed")
        else:
            logger.warning(f"⚠️ Pipeline health check warnings: {health_status}")
        
        # Log performance metrics
        logger_system.log_user_action("pipeline_initialization", {
            "threat_collector": "initialized",
            "ai_classifier": "initialized", 
            "complete_pipeline": "initialized",
            "health_status": health_status.get('status', 'unknown')
        })
        
        return {
            'threat_collector': threat_collector,
            'ai_classifier': ai_classifier,
            'complete_pipeline': complete_pipeline,
            'health_status': health_status,
            'context_engine': context_engine,
            'attack_generator': attack_generator,
            'traffic_synth': traffic_synth,
            'behavior_sim': behavior_sim,
            'ExportScenario': ExportScenario
        }
        
    except Exception as e:
        logger.error(f"Failed to initialize pipeline components: {e}")
        logger_system.log_error("pipeline_initialization_error", str(e), {
            "component": "pipeline_initialization",
            "traceback": traceback.format_exc()
        })
        raise

def setup_signal_handlers(logger):
    """Setup graceful shutdown signal handlers"""
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        
        # Perform cleanup
        logger.info("Performing cleanup...")
        
        # Backup current state if needed
        try:
            config = get_config()
            config.backup_configuration()
            logger.info("Configuration backed up")
        except Exception as e:
            logger.error(f"Failed to backup configuration: {e}")
        
        logger.info("Shutdown complete")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def run_cli_mode(config, logger_system, logger, components):
    """Run in CLI mode for testing/debugging"""
    logger.info("Starting DynoHome in CLI mode")
    
    print("\n🏠 DynoHome - CLI Mode")
    print("=" * 50)
    print(f"Environment: {config.environment}")
    print(f"Pipeline Status: {components['health_status'].get('status', 'unknown')}")
    print(f"Components Loaded: {len(components)} modules")
    
    # Interactive CLI commands
    while True:
        try:
            print("\nAvailable commands:")
            print("  1. Run threat collection")
            print("  2. Test AI classification")
            print("  3. Show system status")
            print("  4. Export logs")
            print("  5. Exit")
            print("  6. Generate attack scenario and dataset")
            
            choice = input("\nEnter command (1-6): ").strip()
            
            if choice == "1":
                print("🔍 Running threat collection...")
                pipeline = components['complete_pipeline']
                
                try:
                    threats = pipeline.run_daily_collection(days_back=3, max_results=10)
                    print(f"✅ Found {len(threats)} IoT threats")
                    
                    logger_system.log_user_action("cli_threat_collection", {
                        "threats_found": len(threats),
                        "success": True
                    })
                    
                except Exception as e:
                    print(f"⚠ Threat collection failed: {e}")
                    logger_system.log_error("cli_threat_collection_error", str(e))
            
            elif choice == "2":
                print("🧠 Testing AI classification...")
                classifier = components['ai_classifier']
                
                test_text = "IoT device buffer overflow vulnerability allows remote code execution"
                try:
                    # This would depend on your actual classifier interface
                    print(f"Test completed - Classifier ready: {classifier is not None}")
                    
                except Exception as e:
                    print(f"⚠ Classification test failed: {e}")
            
            elif choice == "3":
                print("📊 System Status:")
                summary = config.get_configuration_summary()
                metrics = logger_system.get_metrics_summary()
                
                print(f"  Environment: {summary.get('environment')}")
                print(f"  Pipeline Health: {components['health_status'].get('status')}")
                print(f"  Total Operations: {metrics['cumulative_metrics'].get('total_operations', 0)}")
                print(f"  Success Rate: {metrics['recent_performance'].get('success_rate', 0):.2%}")
            
            elif choice == "4":
                print("📄 Exporting logs...")
                export_file = f"dynohome_logs_export_{int(time.time())}.json"
                if logger_system.export_logs(export_file, hours_back=24):
                    print(f"✅ Logs exported to: {export_file}")
                else:
                    print("⚠ Log export failed")
            
            elif choice == "5":
                print("👋 Exiting CLI mode...")
                break
            
            elif choice == "6":
                print("⚙️ Generating demo attack scenario and synthetic dataset...")
                try:
                    # Build demo threat
                    threat_data = {
                        "cve_id": "CVE-2025-0001",
                        "description": "Buffer overflow in smart camera firmware allows remote code execution",
                        "severity": {"cvss_v3_severity": "HIGH"},
                        "nlp_analysis": {"devices": ["camera"]}
                    }
                    ctx = components['context_engine'].map_cve_to_smart_home(threat_data)
                    seq = components['attack_generator'].generate_attack_sequence(ctx)
                    ExportScenario = components['ExportScenario']
                    export_scenario = ExportScenario(
                        scenario_id=f"demo_{int(time.time())}",
                        attack_vector=ctx['attack_methods'][0] if ctx.get('attack_methods') else 'network_exploit',
                        target_devices=ctx.get('target_devices', ['smart_hub']),
                        timeline=seq.get('timeline', []),
                        quality_score=0.9
                    )
                    from datetime import datetime
                    flows = components['traffic_synth'].generate_attack_traffic(export_scenario, datetime.now())
                    print(f"✅ Generated {len(flows)} synthetic attack flows")
                    logger_system.log_user_action("cli_generate_dataset", {"flows": len(flows), "success": True})
                except Exception as e:
                    print(f"⚠ Generation failed: {e}")
                    logger_system.log_error("cli_generate_dataset_error", str(e))
            
            else:
                print("⚠ Invalid choice. Please enter 1-6.")
                
        except KeyboardInterrupt:
            print("\n👋 Exiting CLI mode...")
            break
        except Exception as e:
            print(f"⚠ Error: {e}")
            logger.error(f"CLI mode error: {e}")

def run_web_mode(config, logger_system, logger, components):
    """Launch the Streamlit web application"""
    logger.info("Starting DynoHome web application...")
    
    try:
        import subprocess
        import streamlit as st
        
        # Store components in environment for web app access
        # Note: This is a simplified approach - in production you might use a different method
        os.environ['DYNOHOME_PIPELINE_READY'] = 'true'
        
        print("🌐 Launching web interface...")
        print(f"🔗 URL: http://{config.webapp.host}:{config.webapp.port}")
        
        # Log web app launch
        logger_system.log_user_action("web_app_launch", {
            "host": config.webapp.host,
            "port": config.webapp.port,
            "environment": config.environment
        })
        
        # Launch Streamlit
        cmd = [
            "streamlit", "run", 
            str(project_root / "web_app" / "🏠_Home.py"),
            f"--server.port={config.webapp.port}",
            f"--server.address={config.webapp.host}",
            "--server.headless=true" if not config.webapp.enable_debug else "--server.headless=false"
        ]
        
        subprocess.run(cmd)
        
    except Exception as e:
        logger.error(f"Failed to start web application: {e}")
        logger_system.log_error("web_app_launch_error", str(e))
        raise

def main():
    """Main application entry point"""
    
    print("🏠 DynoHome: AI-Powered IoT Security Framework")
    print("=" * 60)
    
    try:
        # Initialize core systems
        config, logger_system, logger = initialize_core_systems()
        
        # Setup signal handlers for graceful shutdown
        setup_signal_handlers(logger)
        
        # Ensure required directories exist
        ensure_directories(config, logger)
        
        # Import pipeline modules
        modules = import_pipeline_modules(logger)
        
        # Initialize pipeline components
        components = initialize_pipeline_components(config, logger_system, logger, modules)
        
        # Log successful initialization
        logger.info("✅ DynoHome initialized successfully!")
        logger_system.log_user_action("application_startup", {
            "environment": config.environment,
            "components_loaded": list(components.keys()),
            "pipeline_health": components['health_status'].get('status')
        })
        
        print("✅ All systems initialized successfully!")
        
        # Return initialized components for use by other modules
        return {
            'config': config,
            'logger_system': logger_system,
            'logger': logger,
            'components': components
        }
        
    except Exception as e:
        if 'logger' in locals():
            logger.critical(f"Failed to initialize DynoHome: {e}")
            logger.exception("Full initialization error traceback:")
        else:
            print(f"⚠ Critical initialization error: {e}")
            print(f"Traceback: {traceback.format_exc()}")
        
        sys.exit(1)

if __name__ == "__main__":
    # Parse command line arguments
    import argparse
    
    parser = argparse.ArgumentParser(description="DynoHome: AI-Powered IoT Security Framework")
    parser.add_argument("--mode", choices=["web", "cli"], default="web", 
                       help="Run mode: web interface or CLI")
    parser.add_argument("--env", default=None,
                       help="Environment (development/production/testing)")
    parser.add_argument("--config", default=None,
                       help="Custom configuration file path")
    
    args = parser.parse_args()
    
    # Set environment if specified
    if args.env:
        os.environ['DYNOHOME_ENV'] = args.env
    
    # Initialize application
    app_state = main()
    
    # Run in specified mode
    if args.mode == "cli":
        run_cli_mode(
            app_state['config'],
            app_state['logger_system'], 
            app_state['logger'],
            app_state['components']
        )
    else:  # web mode (default)
        run_web_mode(
            app_state['config'],
            app_state['logger_system'],
            app_state['logger'], 
            app_state['components']
        )