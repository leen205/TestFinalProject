# reportgen.py
# -*- coding: utf-8 -*-
"""
PDF report generator — Clear, user-friendly, cyber-style.
Supports Arabic and English, works for clean or suspicious files.
Requires: reportlab, arabic_reshaper, python-bidi, tkinter
"""

import os
from datetime import datetime
from typing import Dict, Any
import arabic_reshaper
from bidi.algorithm import get_display
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.lib import colors
import tkinter as tk
from tkinter import filedialog

# Arabic font (Amiri-Regular.ttf) should be in the same folder
FONT_NAME = "Amiri"
FONT_FILE = "Amiri-Regular.ttf"

def _ar(text: str) -> str:
    """Prepare Arabic text for ReportLab."""
    reshaped = arabic_reshaper.reshape(text)
    return get_display(reshaped)

class PDFReportGenerator:
    def __init__(self, font_file: str = FONT_FILE):
        # Register Arabic font if available
        try:
            pdfmetrics.registerFont(TTFont(FONT_NAME, font_file))
        except Exception:
            pass  # fallback silently

    def generate_pdf(self, results: Dict[str, Any], filename: str = None) -> str:
        """
        Generate a user-friendly PDF report in Arabic.
        results: {
            "basic_analysis": {...},
            "suspicious_items": [...],
            "advanced_stats": {...}
        }
        """

        # --- Handle file save dialog with guaranteed popup ---
        if filename is None:
            root = tk.Tk()
            root.withdraw()  # hide main window
            filename = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf")],
                initialfile="Digital_Forensics_Report.pdf",
                title="اختر مكان حفظ التقرير"
            )
            root.destroy()  # close the hidden root
            if not filename:
                print("تم إلغاء حفظ الملف")
                return ""  # user cancelled

        else:
            if not os.path.isabs(filename):
                filename = os.path.join(os.getcwd(), filename)
            os.makedirs(os.path.dirname(filename), exist_ok=True)

        print("Saving PDF to:", filename)  # Debug: show final path

        c = canvas.Canvas(filename, pagesize=A4)
        width, height = A4

        # Background
        c.setFillColorRGB(0.06, 0.08, 0.12)
        c.rect(0, 0, width, height, fill=True, stroke=False)

        # Title
        c.setFont(FONT_NAME, 20)
        c.setFillColor(colors.cyan)
        c.drawCentredString(width / 2, height - 60, _ar("تقرير تحليل الملف الرقمي"))

        # Subtitle line
        c.setStrokeColor(colors.cyan)
        c.setLineWidth(1.5)
        c.line(40, height - 72, width - 40, height - 72)

        # Date
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        c.setFont(FONT_NAME, 10)
        c.setFillColor(colors.gray)
        c.drawRightString(width - 50, height - 92, _ar(f"تاريخ التقرير: {date_str}"))

        # Y cursor
        y = height - 120
        right_text_x = width - 60

        # --- Basic Info Section ---
        basic = results.get("basic_analysis", {})
        suspicious = results.get("suspicious_items", [])
        adv = results.get("advanced_stats", {})

        file_path = basic.get("file_path", "غير معروف")
        file_type = "غير معروف"
        if file_path != "غير معروف":
            file_type = os.path.splitext(file_path)[1] or "غير معروف"

        c.setFont(FONT_NAME, 14)
        c.setFillColor(colors.whitesmoke)
        c.drawRightString(right_text_x, y, _ar("ملخص سريع"))
        y -= 22

        c.setFont(FONT_NAME, 12)
        c.setFillColor(colors.white)
        c.drawRightString(right_text_x, y, _ar(f"• اسم الملف: {os.path.basename(file_path)}"))
        y -= 18
        c.drawRightString(right_text_x, y, _ar(f"• نوع الملف: {file_type}"))
        y -= 18
        c.drawRightString(right_text_x, y, _ar(f"• إجمالي الأسطر: {basic.get('total_lines', 'غير معروف')}"))
        y -= 18
        c.drawRightString(right_text_x, y, _ar(f"• عدد الأخطاء: {basic.get('errors', 0)}"))
        y -= 18
        c.drawRightString(right_text_x, y, _ar(f"• عدد التحذيرات: {basic.get('warnings', 0)}"))
        y -= 24

        # --- Status ---
        if suspicious:
            status = " الملف يحتوي على نشاطات مشبوهة! تحقق من قسم التهديدات."
            c.setFillColor(colors.orange)
        else:
            status = " الملف سليم. لم يتم العثور على نشاطات مشبوهة."
            c.setFillColor(colors.green)
        c.setFont(FONT_NAME, 12)
        c.drawRightString(right_text_x, y, _ar(status))
        y -= 24

        # --- Threats Section ---
        if suspicious:
            c.setFillColor(colors.cyan)
            c.setFont(FONT_NAME, 13)
            c.drawRightString(right_text_x, y, _ar("التهديدات والاكتشافات"))
            y -= 18

            c.setFont(FONT_NAME, 11)
            c.setFillColor(colors.white)
            for item in suspicious:
                name = item.get("name", "مشكلة")
                level = item.get("risk_level", "-")
                count = item.get("count", 0)
                desc = item.get("description", "")
                c.drawRightString(right_text_x, y, _ar(f"• {name} — مستوى: {level} — مرات الظهور: {count}"))
                y -= 16
                if desc:
                    for part in self._wrap_ar(desc, 80):
                        c.drawRightString(right_text_x, y, _ar(f"   {part}"))
                        y -= 14
                y -= 6
                if y < 120:
                    self._new_page(c, width, height)
                    y = height - 100

        # --- Advanced Stats Section ---
        if adv:
            c.setFillColor(colors.cyan)
            c.setFont(FONT_NAME, 13)
            y -= 6
            c.drawRightString(right_text_x, y, _ar("إحصائيات إضافية"))
            y -= 18
            c.setFont(FONT_NAME, 11)
            c.setFillColor(colors.white)

            for section, data in adv.items():
                c.drawRightString(right_text_x, y, _ar(f"- {section.replace('_', ' ')}:"))
                y -= 14
                if isinstance(data, dict):
                    for k, v in data.items():
                        line = f"    • {k.replace('_', ' ')}: {v}"
                        for part in self._wrap_ar(line, 80):
                            c.drawRightString(right_text_x, y, _ar(part))
                            y -= 14
                        if y < 120:
                            self._new_page(c, width, height)
                            y = height - 100
                else:
                    for part in self._wrap_ar(str(data), 80):
                        c.drawRightString(right_text_x, y, _ar(part))
                        y -= 14
                y -= 6

        # --- Footer ---
        c.setFont(FONT_NAME, 10)
        c.setFillColor(colors.gray)
        footer = "هذا تقرير تلقائي — لمراجعة نهائية راجع فريق الأمن."
        c.drawCentredString(width / 2, 28, _ar(footer))

        c.save()
        return filename

    def _new_page(self, c, width, height):
        c.showPage()
        c.setFillColorRGB(0.06, 0.08, 0.12)
        c.rect(0, 0, width, height, fill=True, stroke=False)

    @staticmethod
    def _wrap_ar(text: str, max_chars: int) -> list:
        """Simple Arabic text wrapper for ReportLab lines."""
        words = text.split()
        lines = []
        cur = ""
        for w in words:
            if len(cur) + len(w) + 1 <= max_chars:
                cur = (cur + " " + w).strip()
            else:
                lines.append(cur)
                cur = w
        if cur:
            lines.append(cur)
        return lines
