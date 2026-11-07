#import tools for creating PDF documents
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

#import tools for formatting the PDF
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from xml.sax.saxutils import escape


#function to create an investigation report
def generate_pdf(report_data, output_path):

    #create the PDF document
    pdf = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm
    )

    #load the default PDF text styles
    styles = getSampleStyleSheet()
    #create an empty list to store PDF content
    content = []

    #add the report title
    content.append(
        Paragraph("EMAIL PHISHING INVESTIGATION REPORT", styles["Title"])
    )
    content.append(Spacer(1, 15))

    #add the email information
    content.append(
        Paragraph("1. Email Information", styles["Heading2"])
    )
    email_details = [
        ["Sender", report_data["sender"]],
        ["Receiver", report_data["receiver"]],
        ["Subject", report_data["subject"]],
        ["Date", report_data["date"]],
        ["Sender Domain", report_data["sender_domain"]]
    ]

    #add the email details as a table
    details_table = Table(email_details, colWidths=[100, 380])
    details_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))
    content.append(details_table)
    content.append(Spacer(1, 15))

    #add the phishing analysis
    content.append(
        Paragraph("2. Phishing Analysis", styles["Heading2"])
    )
    content.append(
        Paragraph(
            f"Risk Score: {report_data['risk_score']}/100",
            styles["BodyText"]
        )
    )
    content.append(
        Paragraph(
            f"Risk Level: {escape(str(report_data['risk_level']))}",
            styles["BodyText"]
        )
    )
    content.append(Spacer(1, 10))

    #add suspicious phrases
    content.append(
        Paragraph("Suspicious Words Found", styles["Heading3"])
    )
    words = report_data["suspicious_words"]
    if words:
        for word in words:
            content.append(Paragraph(f"- {escape(str(word))}", styles["BodyText"]))
    else:
        content.append(Paragraph("None found.", styles["BodyText"]))
    content.append(Spacer(1, 10))

    #add extracted links
    content.append(
        Paragraph("Links Found", styles["Heading3"])
    )
    links = report_data["links"]
    if links:
        for link in links:
            content.append(Paragraph(escape(str(link)), styles["BodyText"]))
    else:
        content.append(Paragraph("None found.", styles["BodyText"]))
    content.append(Spacer(1, 10))

    #add suspicious link warnings
    content.append(
        Paragraph("Suspicious Link Indicators", styles["Heading3"])
    )
    suspicious_links = report_data["suspicious_links"]
    if suspicious_links:
        for link in suspicious_links:
            content.append(
                Paragraph(
                    f"{escape(str(link['url']))} - "
                    f"{escape(str(link['reason']))}",
                    styles["BodyText"]
                )
            )
    else:
        content.append(Paragraph("None found.", styles["BodyText"]))
    content.append(Spacer(1, 15))

    #add a disclaimer to explain the limitations of the tool
    content.append(
        Paragraph("Disclaimer", styles["Heading2"])
    )
    content.append(
        Paragraph(
            "This report contains automated indicators, not a definitive "
            "determination that an email is malicious. Results should be "
            "reviewed by a human investigator.",
            styles["BodyText"]
        )
    )

    #build and save the PDF
    pdf.build(content)