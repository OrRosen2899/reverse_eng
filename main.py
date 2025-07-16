#!/usr/bin/env python3
"""
Advanced Security Analyzer - Reverse Engineering AI Agent
Consolidated single-file implementation
"""

import sys
import os
import json
import time
import logging
import platform
import hashlib
import tempfile
import threading
import traceback
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

# GUI imports
try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QTextEdit, QFileDialog, QProgressBar,
        QGroupBox, QTabWidget, QTableWidget, QTableWidgetItem,
        QMessageBox, QSplitter, QStatusBar, QMenuBar, QAction,
        QHeaderView, QCheckBox, QComboBox, QSpinBox
    )
    from PySide6.QtCore import Qt, QThread, Signal, QTimer, QSettings
    from PySide6.QtGui import QFont, QIcon, QTextCursor
except ImportError:
    print("PySide6 not installed. Run the install script first.")
    sys.exit(1)

# Analysis imports (optional - will show warnings if not available)
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False

try:
    from pdfminer.high_level import extract_text
    PDFMINER_AVAILABLE = True
except ImportError:
    PDFMINER_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import torch
    from transformers import AutoTokenizer, LlamaForCausalLM, pipeline
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# ======================= CORE DATA STRUCTURES =======================

class FileType(Enum):
    PE_EXECUTABLE = "pe_executable"
    OFFICE_MACRO = "office_macro"
    PDF_DOCUMENT = "pdf_document"
    SCRIPT_FILE = "script_file"
    UNKNOWN = "unknown"

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class AnalysisResult:
    file_path: str
    file_type: FileType
    threat_level: ThreatLevel
    confidence_score: float
    features: Dict[str, Any]
    ai_analysis: str
    processing_time: float
    error_messages: List[str]
    warnings: List[str]

# ======================= CONFIGURATION MANAGER =======================

class ConfigManager:
    def __init__(self):
        self.config_dir = self._get_config_dir()
        self.config_file = self.config_dir / 'config.json'
        self.default_config = self._get_default_config()
        self.config = self._load_config()
        
    def _get_config_dir(self) -> Path:
        """Get platform-specific config directory"""
        system = platform.system()
        
        if system == "Windows":
            config_dir = Path(os.environ.get('APPDATA', '')) / 'SecurityAnalyzer'
        elif system == "Darwin":  # macOS
            config_dir = Path.home() / 'Library' / 'Application Support' / 'SecurityAnalyzer'
        else:  # Linux
            config_dir = Path.home() / '.config' / 'SecurityAnalyzer'
        
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'ai_model_name': 'Phind/Phind-CodeLlama-34B-v2',
            'max_file_size': 100 * 1024 * 1024,  # 100MB
            'quarantine_path': str(self.config_dir / 'quarantine'),
            'enable_ai_analysis': True,
            'auto_quarantine': True,
            'log_level': 'INFO',
            'theme': 'light',
            'window_geometry': {'width': 1200, 'height': 800, 'x': 100, 'y': 100}
        }
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                merged_config = self.default_config.copy()
                merged_config.update(config)
                return merged_config
            else:
                return self.default_config.copy()
        except Exception as e:
            print(f"Error loading config: {e}")
            return self.default_config.copy()
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        self.config[key] = value
        self.save_config()

# ======================= SECURITY UTILITIES =======================

class SecurityValidator:
    def __init__(self, config_manager):
        self.config = config_manager
        self.max_file_size = config_manager.get('max_file_size', 100 * 1024 * 1024)
        
    def validate_file(self, file_path: Path) -> Dict[str, Any]:
        """Validate file before analysis"""
        validation_result = {
            'valid': True,
            'warnings': [],
            'errors': []
        }
        
        try:
            if not file_path.exists():
                validation_result['valid'] = False
                validation_result['errors'].append("File does not exist")
                return validation_result
            
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                validation_result['valid'] = False
                validation_result['errors'].append(f"File too large: {file_size} bytes")
                return validation_result
            
            if not os.access(file_path, os.R_OK):
                validation_result['valid'] = False
                validation_result['errors'].append("File not readable")
                return validation_result
            
            if file_size == 0:
                validation_result['warnings'].append("File is empty")
            
        except Exception as e:
            validation_result['valid'] = False
            validation_result['errors'].append(f"Validation error: {str(e)}")
        
        return validation_result

class QuarantineManager:
    def __init__(self, config_manager):
        self.config = config_manager
        self.quarantine_dir = Path(config_manager.get('quarantine_path', './quarantine'))
        self.quarantine_dir.mkdir(exist_ok=True)
        
    def quarantine_file(self, file_path: Path, threat_level: str) -> str:
        """Move suspicious file to quarantine"""
        try:
            import shutil
            
            threat_dir = self.quarantine_dir / threat_level
            threat_dir.mkdir(exist_ok=True)
            
            file_hash = self._calculate_file_hash(file_path)
            sanitized_name = self._sanitize_filename(file_path.name)
            quarantine_filename = f"{file_hash}_{sanitized_name}"
            quarantine_path = threat_dir / quarantine_filename
            
            shutil.copy2(file_path, quarantine_path)
            
            metadata = {
                'original_path': str(file_path),
                'quarantine_time': time.time(),
                'threat_level': threat_level,
                'file_hash': file_hash
            }
            
            metadata_path = quarantine_path.with_suffix('.metadata')
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f)
            
            logging.info(f"File quarantined: {file_path} -> {quarantine_path}")
            return str(quarantine_path)
            
        except Exception as e:
            logging.error(f"Failed to quarantine file: {e}")
            return ""
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return "unknown"
    
    def _sanitize_filename(self, filename: str) -> str:
        safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
        sanitized = ''.join(c if c in safe_chars else '_' for c in filename)
        return sanitized[:100]

# ======================= ANALYSIS ENGINE =======================

class AnalysisEngine:
    def __init__(self, config_manager):
        self.config = config_manager
        self.yara_rules = self._load_yara_rules()
        
    def _load_yara_rules(self) -> Optional[Any]:
        """Load YARA rules for malware detection"""
        if not YARA_AVAILABLE:
            return None
            
        try:
            rules_path = Path("signatures/malware_rules.yar")
            if rules_path.exists():
                return yara.compile(filepath=str(rules_path))
        except Exception as e:
            logging.warning(f"Failed to load YARA rules: {e}")
        return None
    
    def detect_file_type(self, file_path: Path) -> FileType:
        """Detect file type using extensions and basic checks"""
        try:
            extension = file_path.suffix.lower()
            
            # PE executables
            if extension in ['.exe', '.dll', '.sys', '.scr']:
                return FileType.PE_EXECUTABLE
            
            # Office documents with macros
            if extension in ['.docm', '.xlsm', '.pptm', '.doc', '.xls', '.ppt']:
                return FileType.OFFICE_MACRO
            
            # PDF documents
            if extension == '.pdf':
                return FileType.PDF_DOCUMENT
            
            # Script files
            if extension in ['.ps1', '.vbs', '.js', '.sh', '.bat', '.cmd', '.py']:
                return FileType.SCRIPT_FILE
                
        except Exception as e:
            logging.error(f"Error detecting file type: {e}")
        
        return FileType.UNKNOWN
    
    def analyze_pe_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze PE executable files"""
        features = {}
        
        if not PEFILE_AVAILABLE:
            features['error'] = 'pefile library not available'
            return features
        
        try:
            pe = pefile.PE(str(file_path))
            
            # Basic PE information
            features['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            features['image_base'] = hex(pe.OPTIONAL_HEADER.ImageBase)
            features['compilation_timestamp'] = pe.FILE_HEADER.TimeDateStamp
            
            # Import analysis
            imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8')
                    dll_imports = []
                    for imp in entry.imports:
                        if imp.name:
                            dll_imports.append(imp.name.decode('utf-8'))
                    imports.append({'dll': dll_name, 'functions': dll_imports})
            features['imports'] = imports
            
            # Section analysis
            sections = []
            for section in pe.sections:
                section_info = {
                    'name': section.Name.decode('utf-8').strip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'size': section.SizeOfRawData,
                    'entropy': section.get_entropy(),
                    'characteristics': section.Characteristics
                }
                sections.append(section_info)
            features['sections'] = sections
            
            # Calculate imphash
            features['imphash'] = pe.get_imphash()
            
            # LIEF analysis for additional features
            if LIEF_AVAILABLE:
                try:
                    lief_binary = lief.parse(str(file_path))
                    if lief_binary:
                        features['architecture'] = str(lief_binary.header.machine_type)
                        if lief_binary.rich_header:
                            features['rich_header_key'] = hex(lief_binary.rich_header.key)
                except Exception as e:
                    features['lief_error'] = str(e)
            
            # Basic disassembly analysis
            if CAPSTONE_AVAILABLE and sections:
                try:
                    code_section = next((s for s in sections if s['name'] == '.text'), None)
                    if code_section:
                        features['disassembly_sample'] = self._analyze_code_section(pe, code_section)
                except Exception as e:
                    features['disassembly_error'] = str(e)
            
        except Exception as e:
            logging.error(f"Error analyzing PE file: {e}")
            features['error'] = str(e)
        
        return features
    
    def _analyze_code_section(self, pe, code_section) -> Dict[str, Any]:
        """Basic disassembly analysis with Capstone"""
        try:
            section_data = None
            for section in pe.sections:
                if section.Name.decode('utf-8').strip('\x00') == code_section['name']:
                    section_data = section.get_data()
                    break
            
            if not section_data:
                return {'error': 'Could not extract code section data'}
            
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            cs.detail = True
            
            instructions = []
            api_calls = []
            
            sample_size = min(1000, len(section_data))
            for insn in cs.disasm(section_data[:sample_size], 0x1000):
                instructions.append({
                    'address': hex(insn.address),
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str
                })
                
                if insn.mnemonic == 'call':
                    api_calls.append({
                        'address': hex(insn.address),
                        'target': insn.op_str
                    })
            
            return {
                'instruction_count': len(instructions),
                'sample_instructions': instructions[:25],
                'api_calls': api_calls,
                'analysis_coverage': f"{sample_size} bytes analyzed"
            }
            
        except Exception as e:
            return {'error': f'Disassembly failed: {str(e)}'}
    
    def analyze_office_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze Office documents for macros"""
        features = {}
        
        if not OLETOOLS_AVAILABLE:
            features['error'] = 'oletools library not available'
            return features
        
        try:
            vba_parser = VBA_Parser(str(file_path))
            
            if vba_parser.detect_vba_macros():
                features['has_macros'] = True
                
                macros = []
                for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                    macros.append({
                        'filename': vba_filename,
                        'code_sample': vba_code[:500],
                        'code_length': len(vba_code)
                    })
                features['macros'] = macros
                
                suspicious_patterns = []
                results = vba_parser.analyze_macros()
                for result in results:
                    suspicious_patterns.append({
                        'type': result.type,
                        'keyword': result.keyword,
                        'description': result.description
                    })
                features['suspicious_patterns'] = suspicious_patterns
            else:
                features['has_macros'] = False
                
        except Exception as e:
            logging.error(f"Error analyzing Office file: {e}")
            features['error'] = str(e)
        
        return features
    
    def analyze_pdf_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze PDF files for embedded content"""
        features = {}
        
        if not PDFMINER_AVAILABLE:
            features['error'] = 'pdfminer library not available'
            return features
        
        try:
            text_content = extract_text(str(file_path))
            features['text_length'] = len(text_content)
            features['text_sample'] = text_content[:1000]
            
            # Basic PDF analysis
            features['contains_javascript'] = 'javascript' in text_content.lower()
            features['contains_forms'] = '/acroform' in text_content.lower()
            
        except Exception as e:
            logging.error(f"Error analyzing PDF file: {e}")
            features['error'] = str(e)
        
        return features
    
    def analyze_script_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze script files"""
        features = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            features['script_length'] = len(content)
            features['script_content'] = content
            features['line_count'] = content.count('\n')
            
            # Suspicious pattern detection
            content_lower = content.lower()
            features['contains_base64'] = 'base64' in content_lower
            features['contains_powershell'] = 'powershell' in content_lower
            features['contains_cmd'] = 'cmd' in content_lower
            features['contains_download'] = any(word in content_lower for word in ['wget', 'curl', 'invoke-webrequest', 'downloadfile'])
            features['contains_execution'] = any(word in content_lower for word in ['exec', 'eval', 'system', 'shell'])
            
        except Exception as e:
            logging.error(f"Error analyzing script file: {e}")
            features['error'] = str(e)
        
        return features
    
    def calculate_file_hashes(self, file_path: Path) -> Dict[str, str]:
        """Calculate file hashes"""
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
            
        except Exception as e:
            logging.error(f"Error calculating hashes: {e}")
        
        return hashes
    
    def run_yara_scan(self, file_path: Path) -> List[Dict[str, Any]]:
        """Run YARA rules against file"""
        matches = []
        
        if not YARA_AVAILABLE or not self.yara_rules:
            return matches
        
        try:
            yara_matches = self.yara_rules.match(str(file_path))
            for match in yara_matches:
                matches.append({
                    'rule': match.rule,
                    'tags': match.tags,
                    'strings': [str(s) for s in match.strings]
                })
        except Exception as e:
            logging.error(f"YARA scan error: {e}")
        
        return matches
    
    def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Main analysis function"""
        start_time = time.time()
        
        result = AnalysisResult(
            file_path=str(file_path),
            file_type=FileType.UNKNOWN,
            threat_level=ThreatLevel.LOW,
            confidence_score=0.0,
            features={},
            ai_analysis="",
            processing_time=0.0,
            error_messages=[],
            warnings=[]
        )
        
        try:
            # Detect file type
            result.file_type = self.detect_file_type(file_path)
            
            # Calculate file hashes
            result.features['hashes'] = self.calculate_file_hashes(file_path)
            
            # File-specific analysis
            if result.file_type == FileType.PE_EXECUTABLE:
                result.features.update(self.analyze_pe_file(file_path))
            elif result.file_type == FileType.OFFICE_MACRO:
                result.features.update(self.analyze_office_file(file_path))
            elif result.file_type == FileType.PDF_DOCUMENT:
                result.features.update(self.analyze_pdf_file(file_path))
            elif result.file_type == FileType.SCRIPT_FILE:
                result.features.update(self.analyze_script_file(file_path))
            
            # YARA scan
            result.features['yara_matches'] = self.run_yara_scan(file_path)
            
            # Basic threat assessment
            result.threat_level = self._assess_threat_level(result.features)
            result.confidence_score = self._calculate_confidence(result.features)
            
        except Exception as e:
            result.error_messages.append(str(e))
            logging.error(f"Analysis error: {e}")
        
        result.processing_time = time.time() - start_time
        return result
    
    def _assess_threat_level(self, features: Dict[str, Any]) -> ThreatLevel:
        """Assess threat level based on features"""
        threat_indicators = 0
        
        # YARA matches
        if features.get('yara_matches'):
            threat_indicators += len(features['yara_matches']) * 2
        
        # High entropy sections
        if 'sections' in features:
            for section in features['sections']:
                if section.get('entropy', 0) > 7.0:
                    threat_indicators += 1
        
        # Suspicious API imports
        if 'imports' in features:
            suspicious_apis = ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread']
            for dll_import in features['imports']:
                for api in dll_import.get('functions', []):
                    if any(suspicious in api for suspicious in suspicious_apis):
                        threat_indicators += 1
        
        # Macro analysis
        if 'suspicious_patterns' in features:
            threat_indicators += len(features['suspicious_patterns'])
        
        # Script analysis
        script_indicators = ['contains_base64', 'contains_download', 'contains_execution']
        for indicator in script_indicators:
            if features.get(indicator, False):
                threat_indicators += 1
        
        # Determine threat level
        if threat_indicators >= 5:
            return ThreatLevel.CRITICAL
        elif threat_indicators >= 3:
            return ThreatLevel.HIGH
        elif threat_indicators >= 1:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _calculate_confidence(self, features: Dict[str, Any]) -> float:
        """Calculate confidence score for analysis"""
        confidence = 0.5  # Base confidence
        
        if 'hashes' in features and len(features['hashes']) == 3:
            confidence += 0.2
        
        if 'imports' in features and features['imports']:
            confidence += 0.2
        
        if 'yara_matches' in features:
            confidence += 0.1
        
        return min(confidence, 1.0)

# ======================= AI ANALYZER =======================

class AIAnalyzer:
    def __init__(self, config_manager):
        self.config = config_manager
        self.model = None
        self.tokenizer = None
        self.pipeline = None
        self.model_lock = threading.Lock()
        self.model_loaded = False
        
    def load_model(self) -> bool:
        """Load the Hugging Face model"""
        if not AI_AVAILABLE:
            logging.warning("AI libraries not available")
            return False
            
        try:
            model_name = self.config.get('ai_model_name', 'Phind/Phind-CodeLlama-34B-v2')
            
            logging.info(f"Loading AI model: {model_name}")
            
            # Try to load with optimizations
            self.model = LlamaForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16,
                device_map="auto",
                load_in_8bit=True,
                low_cpu_mem_usage=True
            )
            
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            
            self.pipeline = pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer,
                torch_dtype=torch.float16,
                device_map="auto"
            )
            
            self.model_loaded = True
            logging.info("AI model loaded successfully")
            return True
            
        except Exception as e:
            logging.error(f"Failed to load AI model: {e}")
            return False
    
    def analyze_with_ai(self, analysis_result) -> str:
        """Analyze the file using AI model"""
        if not AI_AVAILABLE:
            return "AI analysis not available. Please install transformers and torch libraries."
        
        if not self.model_loaded:
            if not self.load_model():
                return "AI model not available. Analysis based on static features only."
        
        try:
            with self.model_lock:
                prompt = self._format_analysis_prompt(analysis_result)
                
                response = self.pipeline(
                    prompt,
                    max_new_tokens=512,
                    temperature=0.1,
                    do_sample=True,
                    top_p=0.75,
                    top_k=40,
                    pad_token_id=self.tokenizer.eos_token_id
                )
                
                generated_text = response[0]['generated_text']
                assistant_start = generated_text.find("### Assistant\n")
                if assistant_start != -1:
                    ai_response = generated_text[assistant_start + len("### Assistant\n"):].strip()
                else:
                    ai_response = generated_text[len(prompt):].strip()
                
                return ai_response
                
        except Exception as e:
            logging.error(f"AI analysis failed: {e}")
            return f"AI analysis failed: {str(e)}"
    
    def _format_analysis_prompt(self, analysis_result) -> str:
        """Format the analysis results into a prompt for the AI model"""
        features_summary = []
        
        if 'hashes' in analysis_result.features:
            features_summary.append(f"File hashes calculated: MD5, SHA1, SHA256")
        
        if 'imports' in analysis_result.features:
            import_count = len(analysis_result.features['imports'])
            features_summary.append(f"Imports {import_count} DLLs")
        
        if 'yara_matches' in analysis_result.features:
            yara_count = len(analysis_result.features['yara_matches'])
            if yara_count > 0:
                features_summary.append(f"YARA matches: {yara_count}")
        
        if 'suspicious_patterns' in analysis_result.features:
            pattern_count = len(analysis_result.features['suspicious_patterns'])
            if pattern_count > 0:
                features_summary.append(f"Suspicious patterns: {pattern_count}")
        
        prompt = f"""### System Prompt
You are a cybersecurity expert specializing in malware analysis. Analyze the provided file information and provide a detailed assessment.

### User Message
Explain what this file does and whether it's malicious:

File: {analysis_result.file_path}
File Type: {analysis_result.file_type.value}
Threat Level: {analysis_result.threat_level.value}

Key Features:
{chr(10).join(features_summary)}

### Assistant
"""
        
        return prompt

# ======================= ANALYSIS WORKER THREAD =======================

class AnalysisWorker(QThread):
    progress_updated = Signal(str)
    analysis_completed = Signal(AnalysisResult)
    error_occurred = Signal(str)
    
    def __init__(self, file_path, analysis_engine, ai_analyzer=None):
        super().__init__()
        self.file_path = file_path
        self.analysis_engine = analysis_engine
        self.ai_analyzer = ai_analyzer
        self.should_stop = False
        
    def run(self):
        try:
            self.progress_updated.emit("Starting file analysis...")
            
            # Static analysis
            self.progress_updated.emit("Performing static analysis...")
            result = self.analysis_engine.analyze_file(self.file_path)
            
            if self.should_stop:
                return
            
            # AI analysis
            if self.ai_analyzer:
                self.progress_updated.emit("Running AI analysis...")
                result.ai_analysis = self.ai_analyzer.analyze_with_ai(result)
            
            if self.should_stop:
                return
            
            self.progress_updated.emit("Analysis completed successfully")
            self.analysis_completed.emit(result)
            
        except Exception as e:
            self.error_occurred.emit(str(e))
    
    def stop(self):
        self.should_stop = True

# ======================= CUSTOM LOG HANDLER =======================

class LogHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        
    def emit(self, record):
        msg = self.format(record)
        self.text_widget.append(msg)

# ======================= MAIN GUI APPLICATION =======================

class SecurityAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Initialize managers
        self.config_manager = ConfigManager()
        self.analysis_engine = AnalysisEngine(self.config_manager)
        self.ai_analyzer = AIAnalyzer(self.config_manager)
        self.security_validator = SecurityValidator(self.config_manager)
        self.quarantine_manager = QuarantineManager(self.config_manager)
        
        # Initialize GUI
        self.init_ui()
        self.init_logging()
        self.restore_settings()
        self.check_dependencies()
        
        # Analysis state
        self.current_analysis = None
        self.analysis_thread = None
        
    def check_dependencies(self):
        """Check which dependencies are available and show status"""
        missing_deps = []
        
        if not PEFILE_AVAILABLE:
            missing_deps.append("pefile")
        if not LIEF_AVAILABLE:
            missing_deps.append("lief")
        if not CAPSTONE_AVAILABLE:
            missing_deps.append("capstone")
        if not OLETOOLS_AVAILABLE:
            missing_deps.append("oletools")
        if not PDFMINER_AVAILABLE:
            missing_deps.append("pdfminer.six")
        if not YARA_AVAILABLE:
            missing_deps.append("yara-python")
        if not AI_AVAILABLE:
            missing_deps.append("transformers/torch")
        
        if missing_deps:
            self.status_label.setText(f"Missing dependencies: {', '.join(missing_deps)}")
            QMessageBox.warning(
                self, 
                "Missing Dependencies", 
                f"Some analysis features may be limited due to missing dependencies:\n\n{chr(10).join(missing_deps)}\n\nRun the install script to install all dependencies."
            )
        else:
            self.status_label.setText("All dependencies available")
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Advanced Security Analyzer - Reverse Engineering AI Agent")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        main_layout = QHBoxLayout(central_widget)
        
        # Create splitter for resizable panels
        splitter = QSplitter(Qt.Horizontal)
        
        # Left panel - Controls
        left_panel = self.create_control_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Results
        right_panel = self.create_results_panel()
        splitter.addWidget(right_panel)
        
        # Set splitter proportions
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        
        main_layout.addWidget(splitter)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)
        
    def create_control_panel(self) -> QWidget:
        """Create the left control panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # File selection group
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout(file_group)
        
        self.file_path_label = QLabel("No file selected")
        self.file_path_label.setWordWrap(True)
        
        self.browse_button = QPushButton("Browse File...")
        self.browse_button.clicked.connect(self.browse_file)
        
        file_layout.addWidget(self.file_path_label)
        file_layout.addWidget(self.browse_button)
        
        # Analysis options group
        options_group = QGroupBox("Analysis Options")
        options_layout = QVBoxLayout(options_group)
        
        self.enable_ai_check = QCheckBox("Enable AI Analysis")
        self.enable_ai_check.setChecked(self.config_manager.get('enable_ai_analysis', True))
        
        self.auto_quarantine_check = QCheckBox("Auto-quarantine threats")
        self.auto_quarantine_check.setChecked(self.config_manager.get('auto_quarantine', True))
        
        options_layout.addWidget(self.enable_ai_check)
        options_layout.addWidget(self.auto_quarantine_check)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.analyze_button = QPushButton("Start Analysis")
        self.analyze_button.clicked.connect(self.start_analysis)
        self.analyze_button.setEnabled(False)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_analysis)
        self.stop_button.setEnabled(False)
        
        button_layout.addWidget(self.analyze_button)
        button_layout.addWidget(self.stop_button)
        
        # System information
        sys_info_group = QGroupBox("System Information")
        sys_info_layout = QVBoxLayout(sys_info_group)
        
        self.os_info_label = QLabel(f"OS: {platform.system()} {platform.release()}")
        self.python_info_label = QLabel(f"Python: {platform.python_version()}")
        self.ai_status_label = QLabel("AI Model: Not loaded")
        
        sys_info_layout.addWidget(self.os_info_label)
        sys_info_layout.addWidget(self.python_info_label)
        sys_info_layout.addWidget(self.ai_status_label)
        
        # Add all groups to main layout
        layout.addWidget(file_group)
        layout.addWidget(options_group)
        layout.addLayout(button_layout)
        layout.addWidget(sys_info_group)
        layout.addStretch()
        
        return panel
    
    def create_results_panel(self) -> QWidget:
        """Create the right results panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Results tabs
        self.results_tabs = QTabWidget()
        
        # Overview tab
        self.overview_tab = QTextEdit()
        self.overview_tab.setReadOnly(True)
        self.overview_tab.setFont(QFont("Courier", 10))
        self.results_tabs.addTab(self.overview_tab, "Overview")
        
        # Details tab
        self.details_tab = QTextEdit()
        self.details_tab.setReadOnly(True)
        self.details_tab.setFont(QFont("Courier", 9))
        self.results_tabs.addTab(self.details_tab, "Detailed Analysis")
        
        # AI Analysis tab
        self.ai_tab = QTextEdit()
        self.ai_tab.setReadOnly(True)
        self.ai_tab.setFont(QFont("Arial", 10))
        self.results_tabs.addTab(self.ai_tab, "AI Analysis")
        
        # Threats tab
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(3)
        self.threats_table.setHorizontalHeaderLabels(["Type", "Severity", "Description"])
        self.threats_table.horizontalHeader().setStretchLastSection(True)
        self.results_tabs.addTab(self.threats_table, "Threats")
        
        # Log tab
        self.log_tab = QTextEdit()
        self.log_tab.setReadOnly(True)
        self.log_tab.setFont(QFont("Courier", 9))
        self.results_tabs.addTab(self.log_tab, "Analysis Log")
        
        layout.addWidget(self.results_tabs)
        
        return panel
    
    def create_menu_bar(self):
        """Create the menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        open_action = QAction('Open File...', self)
        open_action.setShortcut('Ctrl+O')
        open_action.triggered.connect(self.browse_file)
        file_menu.addAction(open_action)
        
        file_menu.addSeparator()
        
        export_action = QAction('Export Report...', self)
        export_action.setShortcut('Ctrl+E')
        export_action.triggered.connect(self.export_report)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def init_logging(self):
        """Initialize logging system"""
        log_level = self.config_manager.get('log_level', 'INFO')
        
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config_manager.config_dir / 'analyzer.log'),
                LogHandler(self.log_tab)
            ]
        )
        
        logging.info("Security Analyzer started")
    
    def browse_file(self):
        """Browse for file to analyze"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Analyze",
            "",
            "All Files (*)"
        )
        
        if file_path:
            self.set_file_path(file_path)
    
    def set_file_path(self, file_path: str):
        """Set the file path for analysis"""
        self.file_path_label.setText(file_path)
        self.analyze_button.setEnabled(True)
        self.current_file_path = Path(file_path)
        
        # Clear previous results
        self.clear_results()
        
        # Update status
        self.status_label.setText(f"File selected: {Path(file_path).name}")
    
    def clear_results(self):
        """Clear all result displays"""
        self.overview_tab.clear()
        self.details_tab.clear()
        self.ai_tab.clear()
        self.threats_table.setRowCount(0)
    
    def start_analysis(self):
        """Start file analysis"""
        if not hasattr(self, 'current_file_path'):
            QMessageBox.warning(self, "Warning", "Please select a file first.")
            return
        
        # Validate file
        validation_result = self.security_validator.validate_file(self.current_file_path)
        if not validation_result['valid']:
            errors = '\n'.join(validation_result['errors'])
            QMessageBox.critical(self, "File Validation Error", f"Cannot analyze file:\n{errors}")
            return
        
        # Show warnings if any
        if validation_result['warnings']:
            warnings = '\n'.join(validation_result['warnings'])
            reply = QMessageBox.question(
                self, "File Validation Warning", 
                f"File validation warnings:\n{warnings}\n\nContinue with analysis?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return
        
        # Update UI for analysis
        self.analyze_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.status_label.setText("Analysis in progress...")
        
        # Start analysis in separate thread
        self.analysis_thread = AnalysisWorker(
            self.current_file_path,
            self.analysis_engine,
            self.ai_analyzer if self.enable_ai_check.isChecked() else None
        )
        
        self.analysis_thread.progress_updated.connect(self.update_progress)
        self.analysis_thread.analysis_completed.connect(self.analysis_completed)
        self.analysis_thread.error_occurred.connect(self.analysis_error)
        
        self.analysis_thread.start()
    
    def stop_analysis(self):
        """Stop current analysis"""
        if self.analysis_thread and self.analysis_thread.isRunning():
            self.analysis_thread.stop()
            self.analysis_thread.wait()
        
        self.analysis_stopped()
    
    def analysis_stopped(self):
        """Handle analysis stop"""
        self.analyze_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Analysis stopped")
    
    def update_progress(self, message: str):
        """Update progress display"""
        self.status_label.setText(message)
        
        # Add to log
        self.log_tab.append(f"[{time.strftime('%H:%M:%S')}] {message}")
        
        # Auto-scroll log
        cursor = self.log_tab.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.log_tab.setTextCursor(cursor)
    
    def analysis_completed(self, result: AnalysisResult):
        """Handle completed analysis"""
        self.current_analysis = result
        
        # Update UI
        self.analyze_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Analysis completed")
        
        # Display results
        self.display_results(result)
        
        # Handle quarantine if needed
        if (self.auto_quarantine_check.isChecked() and 
            result.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]):
            self.quarantine_file(result)
    
    def analysis_error(self, error_message: str):
        """Handle analysis error"""
        self.analyze_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Analysis failed")
        
        QMessageBox.critical(self, "Analysis Error", f"Analysis failed:\n{error_message}")
    
    def display_results(self, result: AnalysisResult):
        """Display analysis results"""
        # Overview tab
        overview_text = f"""File Analysis Report
{'='*50}

File: {result.file_path}
Type: {result.file_type.value}
Threat Level: {result.threat_level.value}
Confidence: {result.confidence_score:.2f}
Processing Time: {result.processing_time:.2f} seconds

File Hashes:
-----------
"""
        
        if 'hashes' in result.features:
            for hash_type, hash_value in result.features['hashes'].items():
                overview_text += f"{hash_type.upper()}: {hash_value}\n"
        
        overview_text += f"\nErrors: {len(result.error_messages)}\n"
        overview_text += f"Warnings: {len(result.warnings)}\n"
        
        # Add summary of findings
        if 'yara_matches' in result.features and result.features['yara_matches']:
            overview_text += f"\nYARA Detections: {len(result.features['yara_matches'])}\n"
        
        if 'suspicious_patterns' in result.features and result.features['suspicious_patterns']:
            overview_text += f"Suspicious Patterns: {len(result.features['suspicious_patterns'])}\n"
        
        self.overview_tab.setText(overview_text)
        
        # Details tab
        details_text = f"Detailed Analysis Results\n{'='*50}\n\n"
        details_text += f"Raw Features Data:\n{'-'*20}\n"
        details_text += json.dumps(result.features, indent=2, default=str)
        
        if result.error_messages:
            details_text += f"\n\nErrors:\n{'-'*20}\n"
            details_text += '\n'.join(result.error_messages)
        
        if result.warnings:
            details_text += f"\n\nWarnings:\n{'-'*20}\n"
            details_text += '\n'.join(result.warnings)
        
        self.details_tab.setText(details_text)
        
        # AI Analysis tab
        if result.ai_analysis:
            self.ai_tab.setText(result.ai_analysis)
        else:
            self.ai_tab.setText("AI analysis not available or disabled.")
        
        # Threats tab
        self.populate_threats_table(result)
    
    def populate_threats_table(self, result: AnalysisResult):
        """Populate the threats table"""
        threats = []
        
        # Add YARA matches as threats
        if 'yara_matches' in result.features:
            for match in result.features['yara_matches']:
                threats.append({
                    'type': 'YARA Detection',
                    'severity': result.threat_level.value,
                    'description': f"Rule: {match['rule']}"
                })
        
        # Add suspicious patterns
        if 'suspicious_patterns' in result.features:
            for pattern in result.features['suspicious_patterns']:
                threats.append({
                    'type': pattern['type'],
                    'severity': 'Medium',
                    'description': pattern['description']
                })
        
        # Add high entropy sections
        if 'sections' in result.features:
            for section in result.features['sections']:
                if section.get('entropy', 0) > 7.0:
                    threats.append({
                        'type': 'Suspicious Section',
                        'severity': 'Medium',
                        'description': f"High entropy section: {section['name']} (entropy: {section['entropy']:.2f})"
                    })
        
        # Add script-based threats
        script_threats = [
            ('contains_base64', 'Base64 Encoding', 'File contains base64 encoded content'),
            ('contains_download', 'Download Capability', 'File contains download functionality'),
            ('contains_execution', 'Code Execution', 'File contains code execution capabilities')
        ]
        
        for flag, threat_type, description in script_threats:
            if result.features.get(flag, False):
                threats.append({
                    'type': threat_type,
                    'severity': 'Medium',
                    'description': description
                })
        
        # Populate table
        self.threats_table.setRowCount(len(threats))
        
        for row, threat in enumerate(threats):
            self.threats_table.setItem(row, 0, QTableWidgetItem(threat['type']))
            self.threats_table.setItem(row, 1, QTableWidgetItem(threat['severity']))
            self.threats_table.setItem(row, 2, QTableWidgetItem(threat['description']))
    
    def quarantine_file(self, result: AnalysisResult):
        """Quarantine a file"""
        try:
            quarantine_path = self.quarantine_manager.quarantine_file(
                Path(result.file_path),
                result.threat_level.value
            )
            
            if quarantine_path:
                QMessageBox.information(
                    self,
                    "File Quarantined",
                    f"File has been quarantined to:\n{quarantine_path}"
                )
                logging.info(f"File quarantined: {result.file_path}")
            else:
                QMessageBox.warning(
                    self,
                    "Quarantine Failed",
                    "Failed to quarantine file. See log for details."
                )
                
        except Exception as e:
            QMessageBox.critical(
                self,
                "Quarantine Error",
                f"Error quarantining file:\n{str(e)}"
            )
    
    def export_report(self):
        """Export analysis report"""
        if not self.current_analysis:
            QMessageBox.warning(self, "Warning", "No analysis results to export.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Report",
            f"report_{int(time.time())}.txt",
            "Text files (*.txt);;JSON files (*.json)"
        )
        
        if file_path:
            try:
                if file_path.endswith('.json'):
                    # Export as JSON
                    report_data = {
                        'file_path': self.current_analysis.file_path,
                        'file_type': self.current_analysis.file_type.value,
                        'threat_level': self.current_analysis.threat_level.value,
                        'confidence_score': self.current_analysis.confidence_score,
                        'features': self.current_analysis.features,
                        'ai_analysis': self.current_analysis.ai_analysis,
                        'processing_time': self.current_analysis.processing_time,
                        'timestamp': time.time()
                    }
                    
                    with open(file_path, 'w') as f:
                        json.dump(report_data, f, indent=2, default=str)
                else:
                    # Export as text
                    with open(file_path, 'w') as f:
                        f.write(self.overview_tab.toPlainText())
                        f.write("\n\n")
                        f.write(self.details_tab.toPlainText())
                        f.write("\n\n")
                        f.write("AI Analysis:\n")
                        f.write(self.ai_tab.toPlainText())
                
                QMessageBox.information(self, "Export Successful", f"Report exported to:\n{file_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export report:\n{str(e)}")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """Advanced Security Analyzer v1.0

A comprehensive reverse engineering and malware analysis tool
powered by AI and static analysis techniques.

Features:
• PE file analysis with pefile and LIEF
• Office macro analysis with oletools
• PDF analysis with pdfminer.six
• Script analysis
• AI-powered threat assessment
• Automatic quarantine system
• Cross-platform support

Built with Python and PySide6

GitHub: https://github.com/OrRosen2899/reverse_eng.git
"""
        QMessageBox.about(self, "About", about_text)
    
    def restore_settings(self):
        """Restore window settings"""
        geometry = self.config_manager.get('window_geometry', {})
        
        if geometry:
            self.setGeometry(
                geometry.get('x', 100),
                geometry.get('y', 100),
                geometry.get('width', 1200),
                geometry.get('height', 800)
            )
    
    def closeEvent(self, event):
        """Handle window close event"""
        # Save window geometry
        geometry = self.geometry()
        self.config_manager.set('window_geometry', {
            'x': geometry.x(),
            'y': geometry.y(),
            'width': geometry.width(),
            'height': geometry.height()
        })
        
        # Save other settings
        self.config_manager.set('enable_ai_analysis', self.enable_ai_check.isChecked())
        self.config_manager.set('auto_quarantine', self.auto_quarantine_check.isChecked())
        
        # Stop any running analysis
        if self.analysis_thread and self.analysis_thread.isRunning():
            self.analysis_thread.stop()
            self.analysis_thread.wait()
        
        event.accept()

# ======================= MAIN ENTRY POINT =======================

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("Security Analyzer")
    app.setOrganizationName("Security Tools")
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show main window
    window = SecurityAnalyzerGUI()
    window.show()
    
    # Run application
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
