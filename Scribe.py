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

        # Define static junk patterns and blacklists
        self.pe_sections = {".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc", ".idata", ".debug", ".bss"}
        self.junk_blacklist = [
            "this program cannot be run in dos mode",
            "microsoft", "rich", "kernel32", "user32", "msvcp", "vcruntime" # Too generic, filter via other means
        ]
        self.junk_blacklist_strong = [
            "this program cannot be run in dos mode",
            "rich", 
            "0hrich"
        ]

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

    # --- THE SENTINEL ENGINE (IMPROVED) ---

    def fix_wide_text(self, text):
        """Collapses H.y.t.h.e.r.a patterns into Hythera."""
        if len(text) > 8:
            spaced = re.findall(r'[a-zA-Z0-9][\s\x00]', text)
            if len(spaced) > len(text) / 3:
                return text.replace(" ", "").replace("\x00", "")
        return text

    def is_real_word(self, text):
        """Deep heuristic to kill WATAUAVAWH, PE headers, and binary register noise."""
        clean = text.strip()
        if len(clean) < 3: return False
        
        # 1. Hard Blocklist for specific known junk
        clean_l = clean.lower()
        for junk in self.junk_blacklist_strong:
            if junk in clean_l:
                return False

        # 2. PE Section Headers (e.g. .text, .rdata)
        if clean.startswith(".") or clean_l in self.pe_sections:
            return False

        # 3. MSVC Stack Frame Macros (e.g. USVAVAWH, SUVATAUAWH)
        # These are uppercase strings composed only of U, V, W, A, H, S, T, X
        if clean.isupper() and len(clean) > 4:
            macro_chars = set("UVWAHSTX")
            # If 90% of the chars are macro chars, it's garbage
            if sum(1 for c in clean if c in macro_chars) / len(clean) > 0.8:
                return False

        # 4. Random Hex/Address noise (e.g. 0hRich, A^^][)
        if re.match(r'^(0x|0h|[\^\\\[\]\(\)\$]+)', clean):
            return False

        # 5. Vowel and Consonant Logic
        vowels = len(re.findall(r'[aeiouyAEIOUY]', clean))
        
        # Kill all-caps strings with 0 vowels (likely registers/macros) unless very short
        if clean.isupper() and vowels == 0 and len(clean) > 3:
            return False

        # Consonant Clumping
        if re.search(r'[^aeiouyAEIOUY\s]{5,}', clean):
            return False

        # Vowel Balance Check
        if len(clean) > 4 and vowels / len(clean) < 0.15:
            return False

        return True

    def start_async_process(self):
        if self.is_processing: return
        thread = threading.Thread(target=self.process_data_engine)
        thread.daemon = True
        thread.start()

    def process_data_engine(self):
        self.is_processing = True
        self.lbl_status.config(text="SENTINEL SCANNING...")
        self.output_text.delete(1.0, tk.END)
        
        mode = self.analysis_mode.get()
        source = self.raw_data_cache if self.raw_data_cache else self.input_text.get(1.0, tk.END)
        
        if not source or len(str(source).strip()) < 5:
            self.is_processing = False
            return

        results = []
        try:
            source_str = str(source)
            
            if mode == 0: # Normal
                results = re.findall(r'[ -~]{4,}', source_str)
            
            elif mode == 1: # Strict
                lines = re.findall(r'[a-zA-Z0-9\s\.\:\/\-]{5,}', source_str)
                for line in lines:
                    fixed = self.fix_wide_text(line)
                    # Check word by word to be precise
                    words = fixed.split()
                    valid_words = [w for w in words if self.is_real_word(w)]
                    if valid_words:
                        results.append(" ".join(valid_words))
            
            elif mode == 2: # ASM (Cleanest)
                # Only letters and spaces. Force reconstruction first.
                lines = re.findall(r'[a-zA-Z\s\x00]{8,}', source_str)
                for line in lines:
                    fixed = self.fix_wide_text(line)
                    # GRANULAR FILTERING: Split line into words to detach junk from valid text
                    words = fixed.split()
                    valid_words = []
                    for w in words:
                        if self.is_real_word(w):
                            valid_words.append(w)
                    
                    if valid_words:
                        # Reassemble if we found valid words
                        results.append(" ".join(valid_words))
            
            elif mode == 3: # Paths
                fixed_source = self.fix_wide_text(source_str)
                path_patterns = [
                    r'[a-zA-Z]:\\[\w\s\.\-\\]+\.\w+',
                    r'/(?:[\w\.\-]+/)+[\w\.\-]+'
                ]
                for p in path_patterns:
                    results.extend(re.findall(p, fixed_source))

            elif mode == 4: # URL
                fixed_source = self.fix_wide_text(source_str)
                pattern = r'(?:https?://|ws?s://|www\.)[a-zA-Z0-9\-\.\/\?\=\&\%]+'
                results = re.findall(pattern, fixed_source, re.IGNORECASE)

            # Deduplication
            unique_results = []
            for r in results:
                r = r.strip()
                if r not in unique_results and len(r) > 4:
                    unique_results.append(r)

            self.last_results = unique_results
            self.display_results_safe(unique_results)
        except Exception as e:
            print(f"Error: {e}")
        self.is_processing = False

    def display_results_safe(self, results):
        preview = results[:5000]
        self.output_text.insert(tk.END, "\n".join(preview))
        if len(results) > 5000:
            self.output_text.insert(tk.END, f"\n\n... [TRUNCATED] Total: {len(results)}. Save Report to view all.")
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
            self.input_text.insert(tk.END, f"[FILE: {file_path}]")
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
