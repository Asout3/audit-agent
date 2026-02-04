"""Structured logging system for Deep Audit Agent"""
import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional
from rich.logging import RichHandler
from rich.console import Console

console = Console()


class AuditLogger:
    """Centralized logging system with console and file output"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        self._initialized = True
        self.logger = logging.getLogger("deep_audit")
        self.debug_mode = False
        
    def setup(self, debug: bool = False, log_file: str = "audit.log"):
        """Setup logging with both console and file handlers"""
        self.debug_mode = debug
        log_level = logging.DEBUG if debug else logging.INFO
        
        # Clear existing handlers
        self.logger.handlers.clear()
        self.logger.setLevel(log_level)
        
        # Console handler with Rich formatting
        console_handler = RichHandler(
            console=console,
            rich_tracebacks=True,
            tracebacks_show_locals=debug,
            markup=True
        )
        console_handler.setLevel(log_level)
        console_format = logging.Formatter("%(message)s")
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)
        
        # File handler with rotation
        log_path = Path(log_file)
        log_path.parent.mkdir(exist_ok=True)
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)  # Always DEBUG for files
        file_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)
        
        self.info(f"Logger initialized (debug={'ON' if debug else 'OFF'})")
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self.logger.debug(message, extra=kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self.logger.info(message, extra=kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self.logger.warning(message, extra=kwargs)
    
    def error(self, message: str, exc_info: bool = False, **kwargs):
        """Log error message"""
        self.logger.error(message, exc_info=exc_info, extra=kwargs)
    
    def critical(self, message: str, exc_info: bool = True, **kwargs):
        """Log critical message"""
        self.logger.critical(message, exc_info=exc_info, extra=kwargs)
    
    def log_llm_call(self, operation: str, input_size: int, duration: float, success: bool):
        """Log LLM API call with metrics"""
        status = "✓" if success else "✗"
        self.debug(
            f"LLM {status} {operation} | input={input_size} chars | time={duration:.2f}s"
        )
    
    def log_extraction(self, title: str, accepted: bool, reason: str = ""):
        """Log extraction result"""
        status = "ACCEPTED" if accepted else "REJECTED"
        msg = f"Extraction {status}: {title[:50]}"
        if reason:
            msg += f" | Reason: {reason}"
        self.debug(msg)
    
    def log_db_operation(self, operation: str, affected_rows: int = 0, duration: float = 0):
        """Log database operation"""
        self.debug(
            f"DB {operation} | rows={affected_rows} | time={duration:.3f}s"
        )
    
    def log_scoring(self, func_name: str, score: float, reason: str = ""):
        """Log scoring decision"""
        self.debug(
            f"Score: {func_name} = {score:.2f} | {reason}"
        )
    
    def log_rate_limit(self, service: str, wait_time: float):
        """Log rate limit hit"""
        self.warning(
            f"Rate limit hit: {service} | waiting {wait_time:.1f}s"
        )
    
    def log_analysis_progress(self, stage: str, progress: str):
        """Log analysis progress"""
        self.info(f"{stage}: {progress}")


# Global logger instance
_logger = AuditLogger()


def get_logger() -> AuditLogger:
    """Get the global logger instance"""
    return _logger


def setup_logging(debug: bool = False, log_file: str = "audit.log"):
    """Setup the global logger"""
    _logger.setup(debug, log_file)
