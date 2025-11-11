import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
import tkinter as tk
from analysis import analyze_file
from reportgen import PDFReportGenerator
import os

class ForensicsToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Digital Forensics Tool")
        self.root.geometry("950x650")
        self.root.resizable(False, False)

        # ===== App Theme =====
        style = ttk.Style("cyborg")  # Dark modern theme

        # ===== Title =====
        title = ttk.Label(
            root,
            text="🔍 Cyber Digital Forensics Tool",
            font=("Segoe UI", 22, "bold"),
            bootstyle="info"
        )
        title.pack(pady=20)

        # ===== File Selection Section =====
        file_frame = ttk.Frame(root, padding=10)
        file_frame.pack(pady=10)

        ttk.Label(
            file_frame, text="Select a file to analyze:", font=("Segoe UI", 12)
        ).grid(row=0, column=0, padx=10)

        ttk.Button(
            file_frame,
            text="Browse",
            bootstyle="info-outline",
            command=self.browse_file
        ).grid(row=0, column=1, padx=10)

        self.selected_file_label = ttk.Label(
            file_frame,
            text="No file selected",
            bootstyle="inverse-secondary",
            width=60,
            anchor="w"
        )
        self.selected_file_label.grid(row=1, column=0, columnspan=2, pady=5)

        # ===== Buttons Section =====
        button_frame = ttk.Frame(root, padding=10)
        button_frame.pack(pady=10)

        ttk.Button(
            button_frame,
            text="Analyze File",
            bootstyle="success-outline",
            command=self.run_analysis,
            width=22
        ).grid(row=0, column=0, padx=12)

        ttk.Button(
            button_frame,
            text="Generate PDF Report",
            bootstyle="warning-outline",
            command=self.generate_report,
            width=22
        ).grid(row=0, column=1, padx=12)

        ttk.Button(
            button_frame,
            text="Clear Output",
            bootstyle="danger-outline",
            command=self.clear_output,
            width=22
        ).grid(row=0, column=2, padx=12)

        # ===== Output Section =====
        ttk.Label(
            root, text="Analysis Results:", font=("Segoe UI", 12, "bold")
        ).pack(pady=5)

        self.text_output = tk.Text(
            root,
            height=22,
            width=110,
            bg="#1E1E2F",
            fg="#00FFEA",  # Neon cyan for cyber feel
            insertbackground="white",
            wrap="word",
            font=("Consolas", 11)
        )
        self.text_output.pack(padx=10, pady=5)

        # ===== Status Bar =====
        self.status = tk.StringVar(value="Ready")
        status_bar = ttk.Label(
            root,
            textvariable=self.status,
            bootstyle="secondary",
            anchor="w"
        )
        status_bar.pack(side="bottom", fill="x")

        # ===== Store analysis results =====
        self.analysis_results = None

    # ===== File Browsing Function =====
    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if file_path:
            self.selected_file_label.config(text=file_path)
            self.status.set(f"Selected file: {file_path}")

    # ===== Run Analysis Function =====
    def run_analysis(self):
        file_path = self.selected_file_label.cget("text")
        if file_path == "No file selected":
            messagebox.showwarning("Warning", "Please select a file first!")
            self.status.set("Please select a file first!")
            return

        self.status.set("Analyzing file...")
        self.text_output.delete(1.0, tk.END)

        results = analyze_file(file_path)
        self.analysis_results = results

        if isinstance(results, dict):
            # ===== Basic Info =====
            basic = results.get("basic_analysis", {})
            self.text_output.insert(tk.END, "📄 Basic Information:\n", "header")
            if basic:
                for key, value in basic.items():
                    self.text_output.insert(tk.END, f"• {key}: {value}\n")
            else:
                self.text_output.insert(tk.END, "No basic information found.\n")
            self.text_output.insert(tk.END, "\n")

            # ===== Suspicious Items =====
            suspicious = results.get("suspicious_items", [])
            self.text_output.insert(tk.END, "⚠️ Suspicious Items Detected:\n", "header")
            if suspicious:
                for item in suspicious:
                    name = item.get("name", "Unknown")
                    level = item.get("risk_level", "Unknown")
                    self.text_output.insert(tk.END, f"• {name} | Risk Level: {level}\n")
            else:
                self.text_output.insert(tk.END, "No suspicious items detected.\n")
            self.text_output.insert(tk.END, "\n")

            # ===== Advanced Stats =====
            advanced = results.get("advanced_stats", {})
            self.text_output.insert(tk.END, "📈 Advanced Statistics:\n", "header")
            if advanced:
                for section, data in advanced.items():
                    self.text_output.insert(tk.END, f"\n{section}:\n")
                    if data:
                        for key, value in data.items():
                            self.text_output.insert(tk.END, f"  • {key}: {value}\n")
                    else:
                        self.text_output.insert(tk.END, "  No data available.\n")
            else:
                self.text_output.insert(tk.END, "No advanced statistics available.\n")
        else:
            self.text_output.insert(tk.END, "No analysis data returned.")

        self.status.set("Analysis completed!")

    # ===== Generate Report Function =====
    def generate_report(self):
        if not self.analysis_results:
            messagebox.showwarning("Warning", "Please run analysis first!")
            self.status.set("Cannot generate report: no data.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            title="Save PDF Report As"
        )
        if not save_path:
            self.status.set("Report generation cancelled.")
            return

        generator = PDFReportGenerator()
        generator.generate_pdf(self.analysis_results, filename=save_path)
        messagebox.showinfo("Report", f"Report generated successfully!\nSaved as: {save_path}")
        self.status.set("Report generated successfully!")

    # ===== Clear Output Function =====
    def clear_output(self):
        self.text_output.delete(1.0, tk.END)
        self.status.set("Output cleared.")


# ===== Run the App =====
if __name__ == "__main__":
    root = ttk.Window(themename="cyborg")
    app = ForensicsToolApp(root)
    root.mainloop()
