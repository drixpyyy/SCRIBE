import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import re
import threading

class Scribe:
    def __init__(self, root):
        self.root = root
        self.root.title("SCRIBE")
        self.root.geometry("1150x850")
        
        self.analysis_mode = tk.IntVar(value=0)
        self.is_dark_mode = tk.BooleanVar(value=True) 
        self.raw_data_cache = None 
        self.is_processing = False

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
        
        # Added "Paths" mode here
        modes = [("Normal", 0), ("Strict", 1), ("ASM", 2), ("Paths", 3), ("URL", 4)]
        for text, val in modes:
            rb = ttk.Radiobutton(self.mode_frame, text=text, variable=self.analysis_mode, 
                                 value=val, command=self.start_async_process)
            rb.pack(side=tk.LEFT, padx=10)

        self.btn_frame = tk.Frame(self.nav_bar)
        self.btn_frame.pack(side=tk.RIGHT, padx=20)
        self.btn_export = tk.Button(self.btn_frame, text="Save Report", command=self.save_to_file, relief="flat", padx=10, state="disabled")
        self.btn_export.pack(side=tk.LEFT, padx=5)
        self.btn_theme = tk.Button(self.btn_frame, text="Theme", command=self.toggle_theme, relief="flat", padx=10)
        self.btn_theme.pack(side=tk.LEFT, padx=5)
        self.btn_load = tk.Button(self.btn_frame, text="Open File", command=self.load_file, fg="white", bg="#0071e3", relief="flat", padx=15, font=("Segoe UI", 9, "bold"))
        self.btn_load.pack(side=tk.LEFT, padx=5)

        self.main_content = tk.Frame(self.root)
        self.main_content.pack(expand=True, fill=tk.BOTH, padx=40, pady=20)
        self.lbl_status = tk.Label(self.main_content, text="Ready", font=("Segoe UI", 8))
        self.lbl_status.pack(anchor=tk.E)
        self.input_text = tk.Text(self.main_content, height=6, font=("Consolas", 10), bd=0, highlightthickness=1)
        self.input_text.pack(fill=tk.X, pady=(0, 20))
        self.lbl_output = tk.Label(self.main_content, text="EXTRACTED", font=("Segoe UI", 8, "bold"))
        self.lbl_output.pack(anchor=tk.W, pady=(0,5))
        self.output_text = scrolledtext.ScrolledText(self.main_content, font=("Consolas", 11), bd=0, highlightthickness=1, padx=10, pady=10)
        self.output_text.pack(expand=True, fill=tk.BOTH)

    def apply_theme(self):
        t = self.themes["dark"] if self.is_dark_mode.get() else self.themes["light"]
        self.root.configure(bg=t["bg"])
        self.nav_bar.configure(bg=t["surface"], highlightbackground=t["border"])
        self.lbl_title.configure(bg=t["surface"], fg=t["text"])
        self.mode_frame.configure(bg=t["surface"])
        self.btn_frame.configure(bg=t["surface"])
        self.main_content.configure(bg=t["bg"])
        self.lbl_output.configure(bg=t["bg"], fg=t["accent"])
        self.input_text.configure(bg=t["input_bg"], fg=t["text"], highlightbackground=t["border"], insertbackground=t["text"])
        self.output_text.configure(bg=t["input_bg"], fg=t["text"], highlightbackground=t["border"], insertbackground=t["text"])
        self.btn_theme.configure(bg=t["border"], fg=t["text"])
        self.lbl_status.configure(bg=t["bg"], fg=t["text"])

    def toggle_theme(self):
        self.is_dark_mode.set(not self.is_dark_mode.get())
        self.apply_theme()

    def fix_wide_strings(self, text):
        """Fixes UTF-16 spacing (R.o.b.l.o.x -> Roblox)"""
        if len(text) > 4:
            if len(re.findall(r'[a-zA-Z0-9]\s', text)) > len(text) / 3:
                return text.replace(" ", "").replace("\x00", "")
        return text.strip()

    def start_async_process(self):
        if self.is_processing: return
        thread = threading.Thread(target=self.process_data_engine)
        thread.daemon = True
        thread.start()

    def process_data_engine(self):
        self.is_processing = True
        self.lbl_status.config(text="SCANNING...")
        self.output_text.delete(1.0, tk.END)
        
        mode = self.analysis_mode.get()
        source = self.raw_data_cache if self.raw_data_cache else self.input_text.get(1.0, tk.END)
        
        if not source or len(str(source).strip()) < 5:
            self.is_processing = False
            return

        results = []
        try:
            if mode == 0: # Normal
                results = re.findall(r'[ -~]{4,}', str(source))
            
            elif mode == 1: # Strict
                found = re.findall(r'[a-zA-Z0-9\s\.\:\/\-]{5,}', str(source))
                results = [self.fix_wide_strings(x) for x in found if len(x.strip()) > 4]
            
            elif mode == 2: # ASM
                found = re.findall(r'[a-zA-Z\s]{8,}', str(source))
                results = [x.strip() for x in found if len(set(x.lower())) > 3]

            elif mode == 3: # PATHS MODE
                # First heal the text to find spaced-out paths
                clean_content = self.fix_wide_strings(str(source))
                
                # Broad Path Patterns
                # 1. Windows: C:\... or \\Network\...
                # 2. Linux: /usr/bin... or /etc/...
                # 3. Common extensions: .exe, .dll, .txt, .log, .zip, .json, .xml
                path_patterns = [
                    r'[a-zA-Z]:\\[\w\s\.\-\\]+',      # Local Windows
                    r'\\\\[\w\s\.\-\\]+',              # UNC / Network
                    r'/(?:[\w\.\-]+/)+[\w\.\-]+',     # Linux Absolute
                    r'[\w\s\.\-\\]+\.(?:exe|dll|sys|txt|log|json|xml|zip|rar|hpp|cpp|lua)', # File extensions
                    r'\.\.?\\[\w\s\.\-\\]+'            # Relative paths (.\ or ..\)
                ]
                
                for p in path_patterns:
                    found = re.findall(p, clean_content)
                    results.extend(found)

            elif mode == 4: # URL
                cleaned_source = self.fix_wide_strings(str(source))
                pattern = r'(?:https?://|ws?s://|www\.)[a-zA-Z0-9\-\.\/\?\=\&\%]+'
                results = re.findall(pattern, cleaned_source, re.IGNORECASE)

            # Cleanup duplicates and short junk
            unique_results = []
            for r in results:
                r = r.strip()
                if len(r) > 4 and r not in unique_results:
                    unique_results.append(r)

            self.last_results = unique_results
            self.display_results_safe(unique_results)
        except Exception as e:
            print(f"Error: {e}")
        self.is_processing = False

    def display_results_safe(self, results):
        preview = results[:5000]
        output_str = "\n".join(preview)
        if len(results) > 5000:
            output_str += f"\n\n... [TRUNCATED] Total items: {len(results)}. Save Report to view all."
        self.output_text.insert(tk.END, output_str)
        self.btn_export.config(state="normal")
        self.lbl_status.config(text=f"DONE - Found {len(results)}")

    def load_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path: return
        self.lbl_status.config(text="LOADING...")
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            ascii_s = re.findall(b'[ -~]{4,}', data)
            wide_s = re.findall(b'(?:[\x20-\x7E]\x00){4,}', data)
            combined = [s.decode('ascii', errors='ignore') for s in ascii_s]
            combined += [s.decode('utf-16le', errors='ignore') for s in wide_s]
            
            self.raw_data_cache = "\n".join(combined)
            self.input_text.delete(1.0, tk.END)
            self.input_text.insert(tk.END, f"[LOADED: {file_path}]")
            self.start_async_process()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def save_to_file(self):
        if not hasattr(self, 'last_results'): return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(self.last_results))
            messagebox.showinfo("Success", "Report saved.")

if __name__ == "__main__":
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except: pass
    app = Scribe(root)
    root.mainloop()
