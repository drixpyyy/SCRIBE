import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
import threading
import os

class Scribe:
    def __init__(self, root):
        self.root = root
        self.root.title("SCRIBE")
        self.root.geometry("1200x900")
        
        # Core State
        self.analysis_mode = tk.IntVar(value=0)
        self.is_dark_mode = tk.BooleanVar(value=True) 
        self.raw_data_cache = None 
        self.full_binary_data = None
        self.is_processing = False
        self.last_results = []
        self.search_matches = []
        self.current_match_idx = -1
        
        # Dictionary Cache
        self.wordlist = set()
        self.load_wordlist()

        self.themes = {
            "light": {
                "bg": "#f2f2f7", "nav": "#ffffff", "text": "#1c1c1e", 
                "accent": "#007aff", "border": "#d1d1d6", "card": "#ffffff",
                "hover": "#e5e5ea", "highlight": "#ffcc00"
            },
            "dark": {
                "bg": "#000000", "nav": "#1c1c1e", "text": "#ffffff", 
                "accent": "#0a84ff", "border": "#3a3a3c", "card": "#1c1c1e",
                "hover": "#2c2c2e", "highlight": "#ff9500"
            }
        }

        self.setup_ui()
        self.apply_theme()
        
        self.root.bind("<Control-f>", lambda e: self.search_entry.focus_set())
        self.search_entry.bind("<Return>", lambda e: self.jump_to_next_match())

    def load_wordlist(self):
        """Loads the ASMFilter.txt into a high-speed set."""
        try:
            path = os.path.join(os.path.dirname(__file__), "ASMFilter.txt")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    self.wordlist = set(line.strip().lower() for line in f if len(line.strip()) > 1)
            else:
                print("ASMFilter.txt not found.")
        except Exception as e:
            print(f"Error loading wordlist: {e}")

    def setup_ui(self):
        # --- Nav Bar ---
        self.nav_bar = tk.Frame(self.root, height=80, bd=0, highlightthickness=1)
        self.nav_bar.pack(side=tk.TOP, fill=tk.X)
        self.nav_bar.pack_propagate(False)

        self.lbl_title = tk.Label(self.nav_bar, text="SCRIBE", font=("Inter", 20, "bold"))
        self.lbl_title.pack(side=tk.LEFT, padx=40)

        # Search
        search_container = tk.Frame(self.nav_bar)
        search_container.pack(side=tk.RIGHT, padx=30)
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.perform_highlight())
        self.search_entry = tk.Entry(search_container, textvariable=self.search_var, font=("Inter", 10), bd=0, highlightthickness=1, width=25)
        self.search_entry.pack(side=tk.LEFT, ipady=3)

        # Modes Group
        self.mode_frame = tk.Frame(self.nav_bar)
        self.mode_frame.pack(side=tk.LEFT, padx=10)
        
        modes = [("Normal", 0), ("Strict", 1), ("ASM", 2), ("UASM", 6), ("Paths", 3), ("URL", 4), ("Game", 5)]
        for text, val in modes:
            rb = tk.Radiobutton(self.mode_frame, text=text, variable=self.analysis_mode, value=val, 
                                command=self.start_async_process, font=("Inter", 9), 
                                indicatoron=0, bd=0, padx=10, pady=4, relief="flat")
            rb.pack(side=tk.LEFT, padx=1)
            self.style_rb(rb)

        self.btn_frame = tk.Frame(self.nav_bar)
        self.btn_frame.pack(side=tk.RIGHT, padx=10)
        self.btn_load = self.create_btn(self.btn_frame, "Open File", self.load_file, is_primary=True)
        self.btn_load.pack(side=tk.LEFT, padx=5)
        self.btn_export = self.create_btn(self.btn_frame, "Export", self.save_to_file)
        self.btn_export.pack(side=tk.LEFT, padx=2)
        self.btn_theme = self.create_btn(self.btn_frame, "◐", self.toggle_theme)
        self.btn_theme.pack(side=tk.LEFT, padx=2)

        self.main_content = tk.Frame(self.root)
        self.main_content.pack(expand=True, fill=tk.BOTH, padx=50, pady=30)
        self.lbl_status = tk.Label(self.main_content, text="Ready", font=("Inter", 9))
        self.lbl_status.pack(anchor=tk.E, pady=(0,5))

        self.input_text = tk.Text(self.main_content, height=4, font=("Consolas", 10), bd=0, highlightthickness=1)
        self.input_text.pack(fill=tk.X, pady=(0, 15))

        out_container = tk.Frame(self.main_content, highlightthickness=1)
        out_container.pack(expand=True, fill=tk.BOTH)
        self.output_text = tk.Text(out_container, font=("Consolas", 12), bd=0, padx=15, pady=15, wrap=tk.NONE, undo=False)
        sy = tk.Scrollbar(out_container, orient=tk.VERTICAL, command=self.output_text.yview)
        sx = tk.Scrollbar(out_container, orient=tk.HORIZONTAL, command=self.output_text.xview)
        self.output_text.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        sy.pack(side=tk.RIGHT, fill=tk.Y); sx.pack(side=tk.BOTTOM, fill=tk.X); self.output_text.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        self.output_text.tag_configure("find", background="#ff9500", foreground="black")

    def perform_highlight(self):
        self.output_text.tag_remove("find", "1.0", tk.END)
        query = self.search_var.get()
        if not query: return
        start = "1.0"
        while True:
            start = self.output_text.search(query, start, stopindex=tk.END, nocase=True)
            if not start: break
            end = f"{start}+{len(query)}c"
            self.output_text.tag_add("find", start, end); start = end

    def jump_to_next_match(self):
        query = self.search_var.get()
        if not query: return
        matches = []; start = "1.0"
        while True:
            pos = self.output_text.search(query, start, stopindex=tk.END, nocase=True)
            if not pos: break
            matches.append(pos); start = f"{pos}+{len(query)}c"
        if not matches:
            messagebox.showinfo("Scribe Search", f"No results found for '{query}'")
            return
        self.current_match_idx += 1
        if self.current_match_idx >= len(matches): self.current_match_idx = 0
        target_pos = matches[self.current_match_idx]
        self.output_text.see(target_pos); self.output_text.tag_add("sel", target_pos, f"{target_pos}+{len(query)}c")

    def fix_wide_text(self, text):
        if len(text) > 6 and (" " in text or "\x00" in text):
            pattern = re.findall(r'[a-zA-Z0-9][\s\x00]', text)
            if len(pattern) > len(text) / 3:
                text = text.replace(" ", "").replace("\x00", "")
        return "".join(i for i in text if 31 < ord(i) < 127).strip()

    def is_real_word(self, text, mode):
        clean = text.strip()
        if len(clean) < 4: return False
        
        # Kill register prefixes (e.g., IUSVAVAWH -> USVAVAWH)
        if len(clean) > 8 and clean[0] in "IUPX" and clean[1:].isupper():
            clean = clean[1:]

        if mode == 6: # UASM
            if not self.wordlist: return False
            words = clean.lower().split()
            matches = [w for w in words if w in self.wordlist]
            return len(matches) / len(words) >= 0.5

        if mode == 2: # ASM
            if clean.isupper() and len(clean) > 5:
                v = len(re.findall(r'[AEIOUY]', clean))
                if v / len(clean) < 0.25: return False
                if any(clean.startswith(x) for x in ["WATA", "UVWA", "UATA", "VWAU", "USVW"]): return False
            if re.search(r'[^aeiouyAEIOUY\s]{5,}', clean): return False
            if len(re.findall(r'[aeiouyAEIOUY]', clean)) == 0: return False
        return True

    def start_async_process(self):
        if self.is_processing: return
        self.output_text.delete(1.0, tk.END); self.current_match_idx = -1; self.apply_mode_visuals()
        thread = threading.Thread(target=self.process_data_engine); thread.daemon = True; thread.start()

    def process_data_engine(self):
        self.is_processing = True
        self.root.after(0, lambda: self.lbl_status.config(text="RECONSTRUCTING..."))
        mode = self.analysis_mode.get()
        source = self.raw_data_cache if self.raw_data_cache else self.input_text.get(1.0, tk.END)
        if not source or len(str(source).strip()) < 5: self.is_processing = False; return

        results = []
        try:
            cleaned_source = self.fix_wide_text(str(source))
            if mode == 0: results = re.findall(r'[ -~]{4,}', str(source))
            elif mode == 1: 
                lines = re.findall(r'[a-zA-Z0-9\s\.\:\/\-\_]{5,}', cleaned_source)
                results = [x.strip() for x in lines if self.is_real_word(x, 1)]
            elif mode == 2 or mode == 6: # ASM or UASM
                lines = re.findall(r'[a-zA-Z\s]{8,}', cleaned_source)
                results = [x.strip() for x in lines if self.is_real_word(x, mode)]
            elif mode == 3: 
                path_patterns = [r'[a-zA-Z]:\\[\w\s\.\-\\]+\.\w+', r'/(?:[\w\.\-]+/)+[\w\.\-]+']
                for p in path_patterns: results.extend(re.findall(p, cleaned_source))
            elif mode == 4: 
                pattern = r'(?:https?://|ws?s://|www\.)[a-zA-Z0-9\-\.\/\?\=\&\%]+'
                results = re.findall(pattern, cleaned_source, re.IGNORECASE)
            elif mode == 5: # GAME MODE (Renamed from Offsets)
                game_keywords = ["Ammo", "Health", "Gravity", "Jump", "Speed", "Recoil", "FOV", "ESP", "LocalPlayer", "Entity", "Vector", "Matrix", "Offset", "Pointer", "Position", "Rotation", "Scale", "float", "int32", "Multiplier", "Factor", "Amount", "Count", "get_", "set_"]
                lines = cleaned_source.split('\n')
                for line in lines:
                    line = line.strip()
                    has_hex = re.search(r'0[xX][0-9a-fA-F]+', line)
                    has_keyword = any(k.lower() in line.lower() for k in game_keywords)
                    if has_hex or has_keyword:
                        meta_info = ""
                        if self.full_binary_data:
                            target_b = line.encode('ascii', errors='ignore')
                            idx = self.full_binary_data.find(target_b)
                            if idx > 4:
                                prefix = self.full_binary_data[idx-4:idx]
                                if prefix[2] == 0x00: meta_info = f"[ID: 0x{prefix[1:2].hex().upper()}{prefix[0:1].hex().upper()}] "
                        # Clip at random unicode block
                        safe_line = re.split(r'[^\x20-\x7E]{2,}', line)[0]
                        if len(safe_line.strip()) > 3: results.append(f"{meta_info}{safe_line}")

            self.last_results = list(dict.fromkeys(results))
            self.root.after(0, lambda: self.batch_insert(0))
        except Exception as e: print(f"Error: {e}")

    def batch_insert(self, index):
        batch_size = 60; next_index = index + batch_size
        chunk = "\n".join(self.last_results[index:next_index])
        if chunk:
            self.output_text.insert(tk.END, chunk + "\n")
            progress = int((index / len(self.last_results)) * 100)
            self.lbl_status.config(text=f"Loading: {progress}%"); self.root.after(5, lambda: self.batch_insert(next_index))
        else:
            self.lbl_status.config(text=f"DONE - {len(self.last_results)} items"); self.btn_export.config(state="normal"); self.is_processing = False
            self.perform_highlight()

    def create_btn(self, parent, text, cmd, is_primary=False):
        btn = tk.Button(parent, text=text, command=cmd, relief="flat", bd=0, padx=15, pady=6, font=("Inter", 9, "bold"))
        return btn

    def style_rb(self, rb):
        def on_hover(e): 
            if self.analysis_mode.get() != int(rb['value']): rb.configure(bg=self.themes[self.get_mode()]["hover"])
        def on_leave(e): self.apply_mode_visuals()
        rb.bind("<Enter>", on_hover); rb.bind("<Leave>", on_leave)

    def get_mode(self): return "dark" if self.is_dark_mode.get() else "light"

    def apply_theme(self):
        t = self.themes[self.get_mode()]; self.root.configure(bg=t["bg"])
        for w in [self.nav_bar, self.lbl_title, self.mode_frame, self.btn_frame]: w.configure(bg=t["nav"])
        self.lbl_title.configure(fg=t["text"]); self.main_content.configure(bg=t["bg"]); self.lbl_status.configure(bg=t["bg"], fg="#8e8e93")
        self.input_text.configure(bg=t["card"], fg=t["text"], highlightbackground=t["border"], insertbackground=t["text"])
        self.output_text.configure(bg=t["card"], fg=t["text"], insertbackground=t["text"]); self.output_text.master.configure(highlightbackground=t["border"])
        self.search_entry.configure(bg=t["card"], fg=t["text"], highlightbackground=t["border"]); self.btn_load.configure(bg=t["accent"], fg="white")
        self.btn_export.configure(bg=t["nav"], fg=t["text"]); self.btn_theme.configure(bg=t["nav"], fg=t["text"])
        self.output_text.tag_configure("find", background=t["highlight"], foreground="black"); self.apply_mode_visuals()

    def apply_mode_visuals(self):
        t = self.themes[self.get_mode()]
        for child in self.mode_frame.winfo_children():
            if isinstance(child, tk.Radiobutton):
                if self.analysis_mode.get() == int(child['value']): child.configure(bg=t["accent"], fg="white")
                else: child.configure(bg=t["nav"], fg=t["text"])

    def toggle_theme(self): self.is_dark_mode.set(not self.is_dark_mode.get()); self.apply_theme()

    def load_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path: return
        try:
            with open(file_path, 'rb') as f: self.full_binary_data = f.read()
            ascii_s = re.findall(b'[ -~]{4,}', self.full_binary_data)
            wide_s = re.findall(b'(?:[\x20-\x7E]\x00){4,}', self.full_binary_data)
            combined = [s.decode('ascii', errors='ignore') for s in ascii_s]
            combined += [s.decode('utf-16le', errors='ignore') for s in wide_s]
            self.raw_data_cache = "\n".join(combined)
            self.input_text.delete(1.0, tk.END); self.input_text.insert(tk.END, f"[FILE: {file_path}]"); self.start_async_process()
        except Exception as e: messagebox.showerror("Error", str(e))

    def save_to_file(self):
        if not self.last_results: return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f: f.write("\n".join(self.last_results))
            messagebox.showinfo("Success", "Report saved.")

if __name__ == "__main__":
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except: pass
    app = Scribe(root)
    root.mainloop()
