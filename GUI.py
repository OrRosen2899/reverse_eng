import sys, os, platform, traceback
# Attempt to import required libraries, install if missing
REQUIRED_MODULES = [
    "PyQt5", "pefile", "lief", "capstone", "oletools", "pdfminer.six", "requests"
]
for module in REQUIRED_MODULES:
    try:
        __import__(module.split('.')[0])  # import base package (e.g., PyQt5, pefile, etc.)
    except ImportError:
        # Install the module via pip
        try:
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])
        except Exception as e:
            print(f"Failed to install {module}: {e}")

# Now import the modules after ensuring installation
from PyQt5 import QtWidgets, QtGui
from PyQt5.QtWidgets import QApplication, QLabel, QPushButton, QPlainTextEdit, QFileDialog, QHBoxLayout, QVBoxLayout, QWidget
from PyQt5.QtCore import Qt, QThread, pyqtSignal

import pefile
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from oletools.olevba import VBA_Parser
from pdfminer.high_level import extract_text  # not used for JS but could extract text if needed
import re
import requests

# Worker thread for analysis
class AnalysisThread(QThread):
    result_ready = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
    
    def run(self):
        try:
            file_path = self.file_path
            _, extension = os.path.splitext(file_path)
            extension = extension.lower()
            prompt = ""
            # Determine file type by extension and process accordingly
            if extension == ".exe":
                # Parse PE file
                pe = pefile.PE(file_path)
                # Determine architecture (32-bit vs 64-bit)
                arch = "x86_64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"
                # Extract .text section bytes
                text_bytes = b""
                for section in pe.sections:
                    name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    if name == ".text":
                        text_bytes = section.get_data()
                        break
                if not text_bytes:
                    raise Exception("No .text section found in executable.")
                # Disassemble using capstone
                md = Cs(CS_ARCH_X86, CS_MODE_64 if arch == "x86_64" else CS_MODE_32)
                assembly_lines = []
                # Use the entry point RVA as start address (optional: image base + RVA for actual VA)
                start_addr = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
                for insn in md.disasm(text_bytes, start_addr):
                    assembly_lines.append(f"0x{insn.address:X}:\t{insn.mnemonic}\t{insn.op_str}")
                    # Optional: limit number of instructions to avoid huge output
                    if len(assembly_lines) >= 1000:  # cap at 1000 instructions for safety
                        assembly_lines.append("... (truncated)")
                        break
                assembly_code = "\n".join(assembly_lines)
                prompt = (f"Convert this {arch} assembly into C-like pseudocode and explain what it does. "
                          f"Is it malicious?\n\n{assembly_code}")
            
            elif extension in [".docm", ".xlsm"]:
                parser = VBA_Parser(file_path)
                vba_code = ""
                if parser.exists_macros:
                    macros = parser.extract_all_macros()
                    for (_, _, vba_filename, vba_content) in macros:
                        if vba_content:
                            vba_code += f"Module {vba_filename}:\n{vba_content}\n\n"
                else:
                    vba_code = "(No VBA macros found.)"
                parser.close()
                prompt = ("Explain what this VBA macro code does and whether it's malicious:\n\n" 
                          f"{vba_code}")
            
            elif extension == ".pdf":
                # Read PDF and search for JavaScript
                with open(file_path, 'rb') as f:
                    pdf_data = f.read()
                js_code = ""
                # Find JavaScript in ( ) or < >
                matches = re.findall(rb'/J(?:avaScript|S)\s*\((.*?)\)', pdf_data, flags=re.DOTALL)
                for m in matches:
                    try:
                        js_code += m.decode('latin1') + "\n"
                    except:
                        js_code += m.decode('latin1', errors='ignore') + "\n"
                matches_hex = re.findall(rb'/J(?:avaScript|S)\s*<([0-9A-Fa-f]+)>', pdf_data)
                for m in matches_hex:
                    try:
                        js_bytes = bytes.fromhex(m.decode('ascii', errors='ignore'))
                        js_code += js_bytes.decode('latin1') + "\n"
                    except:
                        # If decoding fails, skip
                        continue
                if js_code.strip() == "":
                    js_code = "(No embedded JavaScript code found in the PDF.)"
                prompt = ("The following is JavaScript code extracted from a PDF file. "
                          "Explain what this code does and whether the PDF is malicious:\n\n"
                          f"{js_code}")
            
            elif extension in [".ps1", ".js", ".vbs", ".sh", ".bat"]:
                # Read script text
                with open(file_path, 'r', errors='ignore') as f:
                    code_text = f.read()
                prompt = (f"Explain what the following script does and whether it is malicious:\n\n{code_text}")
            
            else:
                raise Exception("Unsupported file type selected.")
            
            # Prepare to call AI model
            api_token = os.getenv("HF_API_TOKEN") or os.getenv("HUGGINGFACEHUB_API_TOKEN")
            if not api_token:
                raise Exception("No Hugging Face API token provided. Set HF_API_TOKEN environment variable.")
            api_url = "https://api-inference.huggingface.co/models/Phind/Phind-CodeLlama-34B-v2"
            headers = {"Authorization": f"Bearer {api_token}"}
            data = {"inputs": prompt, "max_new_tokens": 500, "temperature": 0.2}
            resp = requests.post(api_url, headers=headers, json=data, timeout=300)
            if resp.status_code != 200:
                raise Exception(f"Model API returned {resp.status_code}: {resp.text}")
            result = resp.json()
            if isinstance(result, list) and len(result) > 0:
                analysis_text = result[0].get("generated_text", "").strip()
            else:
                # If result is not the usual list, just stringify it
                analysis_text = str(result)
            # Emit the result back to GUI
            self.result_ready.emit(analysis_text)
        except Exception as e:
            err_msg = f"Error during analysis: {e}\n" + traceback.format_exc()
            self.error.emit(err_msg)

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Reverse Engineering AI Assistant")
        self.resize(800, 600)
        # Layout setup
        layout = QVBoxLayout(self)
        # OS label
        os_name = platform.system()  # e.g. 'Windows', 'Linux', 'Darwin'
        env_label = QLabel(f"Operating System: {os_name}")
        env_label.setAlignment(Qt.AlignCenter)
        env_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(env_label)
        # File picker controls
        hbox = QHBoxLayout()
        self.path_edit = QtWidgets.QLineEdit()
        self.path_edit.setPlaceholderText("Select a file to analyze...")
        self.path_edit.setReadOnly(True)
        browse_btn = QPushButton("Browse")
        hbox.addWidget(self.path_edit)
        hbox.addWidget(browse_btn)
        layout.addLayout(hbox)
        # Analysis output box
        self.output_box = QPlainTextEdit()
        self.output_box.setReadOnly(True)
        # Monospace font for clarity
        font = QtGui.QFont("Courier New" if os_name == "Windows" else "Courier", 10)
        self.output_box.setFont(font)
        layout.addWidget(self.output_box)
        # Connect browse button
        browse_btn.clicked.connect(self.select_file)
        # Keep track of analysis thread
        self.analysis_thread = None
    
    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Analyze", "", 
            "Executable/Macro/PDF/Script Files (*.exe *.docm *.xlsm *.pdf *.ps1 *.js *.vbs *.sh *.bat);;All Files (*)")
        if file_path:
            self.path_edit.setText(file_path)
            self.output_box.setPlainText("Analyzing the file, please wait...")
            # Disable the UI while analyzing (optional)
            # self.path_edit.setEnabled(False)
            # Now start analysis thread
            self.analysis_thread = AnalysisThread(file_path)
            self.analysis_thread.result_ready.connect(self.show_result)
            self.analysis_thread.error.connect(self.show_error)
            self.analysis_thread.start()
    
    def show_result(self, text):
        # Display the AI analysis result
        self.output_box.setPlainText(text)
        # Re-enable UI if it was disabled
        # self.path_edit.setEnabled(True)
        # Optionally, scroll to top
        self.output_box.verticalScrollBar().setValue(0)
        # Stop thread (thread will be deleted automatically after finishing in PyQt)
        self.analysis_thread = None
    
    def show_error(self, error_text):
        # Display error message in the output box
        self.output_box.setPlainText(error_text)
        # Re-enable UI
        # self.path_edit.setEnabled(True)
        self.analysis_thread = None

# Main entry point
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
