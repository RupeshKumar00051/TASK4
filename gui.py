import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from encryption_tool.core import FileEncryptor
import threading

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced File Encryption Tool")
        self.root.geometry("600x400")
        self.encryptor = FileEncryptor()
        
        self.create_widgets()
        
    def create_widgets(self):
        # Notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # File encryption tab
        self.file_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.file_frame, text="File Operations")
        self.setup_file_tab()
        
        # Directory encryption tab
        self.dir_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dir_frame, text="Directory Operations")
        self.setup_dir_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(
            self.root, 
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.pack(fill=tk.X)
        
    def setup_file_tab(self):
        # Input file selection
        ttk.Label(self.file_frame, text="Input File:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.input_file = tk.StringVar()
        ttk.Entry(self.file_frame, textvariable=self.input_file, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.file_frame, text="Browse...", command=self.browse_input_file).grid(row=0, column=2, padx=5, pady=5)
        
        # Output file selection
        ttk.Label(self.file_frame, text="Output File:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.output_file = tk.StringVar()
        ttk.Entry(self.file_frame, textvariable=self.output_file, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(self.file_frame, text="Browse...", command=self.browse_output_file).grid(row=1, column=2, padx=5, pady=5)
        
        # Password
        ttk.Label(self.file_frame, text="Password:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.password = tk.StringVar()
        ttk.Entry(self.file_frame, textvariable=self.password, show="*", width=50).grid(row=2, column=1, padx=5, pady=5)
        
        # Buttons
        ttk.Button(self.file_frame, text="Encrypt", command=self.encrypt_file).grid(row=3, column=1, padx=5, pady=5, sticky=tk.E)
        ttk.Button(self.file_frame, text="Decrypt", command=self.decrypt_file).grid(row=3, column=2, padx=5, pady=5, sticky=tk.W)
        
    def setup_dir_tab(self):
        # Input directory selection
        ttk.Label(self.dir_frame, text="Input Directory:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.input_dir = tk.StringVar()
        ttk.Entry(self.dir_frame, textvariable=self.input_dir, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.dir_frame, text="Browse...", command=self.browse_input_dir).grid(row=0, column=2, padx=5, pady=5)
        
        # Output directory selection
        ttk.Label(self.dir_frame, text="Output Directory:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.output_dir = tk.StringVar()
        ttk.Entry(self.dir_frame, textvariable=self.output_dir, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(self.dir_frame, text="Browse...", command=self.browse_output_dir).grid(row=1, column=2, padx=5, pady=5)
        
        # Password
        ttk.Label(self.dir_frame, text="Password:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.dir_password = tk.StringVar()
        ttk.Entry(self.dir_frame, textvariable=self.dir_password, show="*", width=50).grid(row=2, column=1, padx=5, pady=5)
        
        # Buttons
        ttk.Button(self.dir_frame, text="Encrypt Directory", command=self.encrypt_directory).grid(row=3, column=1, padx=5, pady=5, sticky=tk.E)
        ttk.Button(self.dir_frame, text="Decrypt Directory", command=self.decrypt_directory).grid(row=3, column=2, padx=5, pady=5, sticky=tk.W)
        
    def browse_input_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.input_file.set(filename)
            if not self.output_file.get():
                self.output_file.set(filename + '.enc')
    
    def browse_output_file(self):
        filename = filedialog.asksaveasfilename()
        if filename:
            self.output_file.set(filename)
    
    def browse_input_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.input_dir.set(directory)
            if not self.output_dir.get():
                self.output_dir.set(directory + '_encrypted')
    
    def browse_output_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.output_dir.set(directory)
    
    def encrypt_file(self):
        self.run_operation(
            self.encryptor.encrypt_file,
            self.input_file.get(),
            self.output_file.get(),
            self.password.get()
        )
    
    def decrypt_file(self):
        self.run_operation(
            self.encryptor.decrypt_file,
            self.input_file.get(),
            self.output_file.get(),
            self.password.get()
        )
    
    def encrypt_directory(self):
        self.run_operation(
            self.encryptor.encrypt_directory,
            self.input_dir.get(),
            self.output_dir.get(),
            self.dir_password.get()
        )
    
    def decrypt_directory(self):
        self.run_operation(
            self.encryptor.decrypt_directory,
            self.input_dir.get(),
            self.output_dir.get(),
            self.dir_password.get()
        )
    
    def run_operation(self, func, *args):
        if not all(args):
            messagebox.showerror("Error", "All fields are required")
            return
        
        self.status_var.set("Working...")
        self.root.config(cursor="watch")
        
        def operation():
            try:
                success = func(*args)
                self.root.after(0, self.operation_complete, success)
            except Exception as e:
                self.root.after(0, self.operation_failed, str(e))
        
        threading.Thread(target=operation, daemon=True).start()
    
    def operation_complete(self, success):
        self.root.config(cursor="")
        if success:
            messagebox.showinfo("Success", "Operation completed successfully")
            self.status_var.set("Ready")
        else:
            messagebox.showerror("Error", "Operation failed")
            self.status_var.set("Operation failed")
    
    def operation_failed(self, error):
        self.root.config(cursor="")
        messagebox.showerror("Error", f"Operation failed: {error}")
        self.status_var.set(f"Error: {error}")

def run_gui():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    run_gui()