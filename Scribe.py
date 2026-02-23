import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import re

class Scribe:
    def __init__(self, root):
        self.root = root
        self.root.title("SCRIBE")
        self.root.geometry("1150x850")
        
        self.analysis_mode = tk.IntVar(value=0)
        self.is_dark_mode = tk.BooleanVar(value=False)
        self.cached_file_strings = None 

        self.themes = {
            "light": {
                "bg": "#f5f5f7", "surface": "#ffffff", "text": "#1d1d1f", 
                "accent": "#0071e3", "border": "#d2d2d7", "input_bg": "#ffffff"
            },
            "dark": {
                "bg": "#121212", "surface": "#1e1e1e", "text": "#ffffff", 
                "accent": "#0a84ff", "border": "#333333", "input_bg": "#252525"
            }
        }

        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        self.nav_bar = tk.Frame(self.root, height=70, bd=0, highlightthickness=1)
        self.nav_bar.pack(side=tk.TOP, fill=tk.X)
        self.nav_bar.pack_propagate(False)

        self.lbl_title = tk.Label(self.nav_bar, text="SCRIBE", font=("Segoe UI", 18, "bold"))
        self.lbl_title.pack(side=tk.LEFT, padx=30)

        self.mode_frame = tk.Frame(self.nav_bar)
        self.mode_frame.pack(side=tk.LEFT, padx=20)

        # Mode List
        modes = [("Normal", 0), ("Strict", 1), ("ASM", 2), ("URL", 3), ("URL ASM", 4)]
        for text, val in modes:
            rb = ttk.Radiobutton(self.mode_frame, text=text, variable=self.analysis_mode, 
                                 value=val, command=self.process_data)
            rb.pack(side=tk.LEFT, padx=10)

        self.btn_frame = tk.Frame(self.nav_bar)
        self.btn_frame.pack(side=tk.RIGHT, padx=20)

        self.btn_theme = tk.Button(self.btn_frame, text="Toggle Theme", command=self.toggle_theme, 
                                   relief="flat", padx=10)
        self.btn_theme.pack(side=tk.LEFT, padx=5)

        self.btn_load = tk.Button(self.btn_frame, text="Open File", command=self.load_file, 
                                  fg="white", bg="#0071e3", relief="flat", padx=15, font=("Segoe UI", 9, "bold"))
        self.btn_load.pack(side=tk.LEFT, padx=5)

        self.main_content = tk.Frame(self.root)
        self.main_content.pack(expand=True, fill=tk.BOTH, padx=40, pady=20)

        self.lbl_input = tk.Label(self.main_content, text="INPUT", font=("Segoe UI", 8, "bold"))
        self.lbl_input.pack(anchor=tk.W, pady=(0,5))
        
        self.input_text = tk.Text(self.main_content, height=6, font=("Consolas", 10), bd=0, highlightthickness=1)
        self.input_text.pack(fill=tk.X, pady=(0, 20))
        self.input_text.bind("<KeyRelease>", lambda e: self.on_input_change())

        self.lbl_output = tk.Label(self.main_content, text="EXTRACTED", font=("Segoe UI", 8, "bold"))
        self.lbl_output.pack(anchor=tk.W, pady=(0,5))
        
        self.output_text = scrolledtext.ScrolledText(self.main_content, font=("Consolas", 11), 
                                                    bd=0, highlightthickness=1, padx=10, pady=10)
        self.output_text.pack(expand=True, fill=tk.BOTH)

    def apply_theme(self):
        t = self.themes["dark"] if self.is_dark_mode.get() else self.themes["light"]
        self.root.configure(bg=t["bg"])
        self.nav_bar.configure(bg=t["surface"], highlightbackground=t["border"])
        self.lbl_title.configure(bg=t["surface"], fg=t["text"])
        self.mode_frame.configure(bg=t["surface"])
        self.btn_frame.configure(bg=t["surface"])
        self.main_content.configure(bg=t["bg"])
        self.lbl_input.configure(bg=t["bg"], fg=t["accent"])
        self.lbl_output.configure(bg=t["bg"], fg=t["accent"])
        self.input_text.configure(bg=t["input_bg"], fg=t["text"], highlightbackground=t["border"])
        self.output_text.configure(bg=t["input_bg"], fg=t["text"], highlightbackground=t["border"])
        self.btn_theme.configure(bg=t["border"], fg=t["text"])

    def toggle_theme(self):
        self.is_dark_mode.set(not self.is_dark_mode.get())
        self.apply_theme()

    def fix_wide_strings(self, text):
        """Collapses UTF-16 style spacing (e.g. h t t p -> http)"""
        # If every other char is a space or null, it's wide
        if len(text) > 4:
            pattern_match = len(re.findall(r'[a-zA-Z0-9]\s', text))
            if pattern_match > len(text) / 3:
                return text.replace(" ", "").replace("\x00", "")
        return text.strip()

    def on_input_change(self):
        self.cached_file_strings = None 
        self.process_data()

    def process_data(self):
        self.output_text.delete(1.0, tk.END)
        mode = self.analysis_mode.get()
        
        raw_source = self.cached_file_strings if self.cached_file_strings else self.input_text.get(1.0, tk.END)
        if not raw_source or len(str(raw_source).strip()) < 5: return

        results = []
        if mode == 0: # Normal
            results = re.findall(r'[ -~]{4,}', str(raw_source))
        elif mode == 1: # Strict
            found = re.findall(r'[a-zA-Z0-9\s\.\:\/\-]{5,}', str(raw_source))
            results = [self.fix_wide_strings(x) for x in found if len(x.strip()) > 4]
        elif mode == 2: # ASM
            found = re.findall(r'[a-zA-Z\s]{8,}', str(raw_source))
            results = [x.strip() for x in found if len(set(x.lower())) > 3]
        elif mode == 3: # URL (Broad/Fuzzy)
            # 1. First, collapse everything to catch h.t.t.p.s. links
            content = self.fix_wide_strings(str(raw_source))
            # 2. Look for any protocol start
            # We look for http, https, ws, wss or even just //
            lines = content.split('\n')
            for line in lines:
                # Find the index of protocol
                for proto in ['https://', 'http://', 'ws://', 'wss://', 'ftp://']:
                    idx = line.lower().find(proto)
                    if idx != -1:
                        # Grab from the protocol to the end of the line
                        # then refine to hit a common TLD or space
                        potential = line[idx:].strip()
                        # If we find a space, cut it there
                        space_idx = potential.find(' ')
                        if space_idx != -1:
                            results.append(potential[:space_idx])
                        else:
                            results.append(potential)
        elif mode == 4: # URL ASM (Strict)
            pattern = r'(?:https?://|ws?s://|www\.)[\w\-\.\/\?\=\&\%\#]+'
            pre_cleaned = self.fix_wide_strings(str(raw_source))
            results = re.findall(pattern, pre_cleaned, re.IGNORECASE)

        # Remove duplicates while preserving order
        unique_results = []
        for x in results:
            if x and x not in unique_results: unique_results.append(x)

        self.output_text.insert(tk.END, "\n".join(unique_results))

    def load_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path: return
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Extract ASCII
            ascii_strings = re.findall(b'[ -~]{4,}', data)
            # Extract Wide (UTF-16LE)
            wide_strings = re.findall(b'(?:[\x20-\x7E]\x00){4,}', data)
            
            combined = []
            for s in ascii_strings: combined.append(s.decode('ascii', errors='ignore'))
            for s in wide_strings: combined.append(s.decode('utf-16le', errors='ignore'))
            
            self.input_text.delete(1.0, tk.END)
            self.input_text.insert(tk.END, f"[FILE: {file_path}]")
            self.cached_file_strings = "\n".join(combined)
            self.process_data()
        except Exception as e:
            self.output_text.insert(tk.END, f"Error: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except: pass
    app = Scribe(root)
    root.mainloop()
