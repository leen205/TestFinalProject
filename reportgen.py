from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
import os
import arabic_reshaper
from bidi.algorithm import get_display

class PDFReportGenerator:
    def __init__(self, font_file="Amiri-Regular.ttf"):
        # تسجيل الخط العربي
        pdfmetrics.registerFont(TTFont("Amiri", font_file))

    def generate_pdf(self, results, output_dir=None):
        if output_dir is None:
            output_dir = os.getcwd()

        os.makedirs(output_dir, exist_ok=True)
        filename = os.path.join(output_dir, "Digital_Forensics_Report.pdf")

        c = canvas.Canvas(filename, pagesize=A4)
        width, height = A4

        c.setFont("Amiri", 14)

        # تصحيح النص العربي
        title = "تقرير التحليل الجنائي الرقمي"
        reshaped_title = arabic_reshaper.reshape(title)
        bidi_title = get_display(reshaped_title)

        c.drawCentredString(width/2, height-50, bidi_title)

        y = height - 100

        if isinstance(results, dict):
            for section, data in results.items():
                section_text = get_display(arabic_reshaper.reshape(f"--- {section} ---"))
                c.setFont("Amiri", 12)
                c.drawString(50, y, section_text)
                y -= 20
                if isinstance(data, dict) and data:
                    for key, value in data.items():
                        line = get_display(arabic_reshaper.reshape(f"{key}: {value}"))
                        c.drawString(60, y, line)
                        y -= 20
                        if y < 50:
                            c.showPage()
                            c.setFont("Amiri", 12)
                            y = height - 50
                elif isinstance(data, list) and data:
                    for item in data:
                        line = get_display(arabic_reshaper.reshape(f"- {item}"))
                        c.drawString(60, y, line)
                        y -= 20
                        if y < 50:
                            c.showPage()
                            c.setFont("Amiri", 12)
                            y = height - 50
                else:
                    c.drawString(60, y, get_display(arabic_reshaper.reshape("لا توجد بيانات")))
                    y -= 20
        else:
            c.drawString(50, y, get_display(arabic_reshaper.reshape("لا توجد نتائج تحليل")))

        c.save()
        return filename
