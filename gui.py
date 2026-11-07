#import Tkinter for the graphical interface
import tkinter as tk
#import file tools and error message boxes
from tkinter import filedialog, messagebox
#import the scrolling text box
from tkinter.scrolledtext import ScrolledText

#import our existing email investigation functions
from email_parser import read_email
from phishing_detector import (
    check_suspicious_words,
    extract_links,
    check_suspicious_links,
    check_sender,
    calculate_risk
)
from report_generator import generate_pdf


# =====================================
# CREATE THE APPLICATION WINDOW
# =====================================

root = tk.Tk()

root.title("Email Phishing Investigator")

root.geometry("1000x750")

root.minsize(850, 650)

# Set the background colour
root.configure(bg="#151a24")


# Store the latest investigation results
# This will allow us to export them later
latest_report = None


# =====================================
# CREATE THE HEADER
# =====================================

header = tk.Frame(
    root,
    bg="#151a24"
)

header.pack(fill="x", padx=25, pady=20)


# Display the application title
title = tk.Label(
    header,
    text="EMAIL PHISHING INVESTIGATOR",
    font=("Arial", 22, "bold"),
    bg="#151a24",
    fg="white"
)

title.pack(anchor="w")


# Display a short description
subtitle = tk.Label(
    header,
    text="Email Security Analysis and Digital Forensics Tool",
    font=("Arial", 10),
    bg="#151a24",
    fg="#9ca3af"
)

subtitle.pack(anchor="w", pady=5)


# =====================================
# CREATE THE BUTTON AREA
# =====================================

button_frame = tk.Frame(
    root,
    bg="#151a24"
)

button_frame.pack(fill="x", padx=25, pady=10)


# =====================================
# CREATE THE RISK ASSESSMENT AREA
# =====================================

risk_frame = tk.Frame(
    root,
    bg="#252d3a",
    padx=15,
    pady=12
)

risk_frame.pack(fill="x", padx=25, pady=10)


# Display the risk score
risk_score_label = tk.Label(
    risk_frame,
    text="Risk Score: --",
    font=("Arial", 14, "bold"),
    bg="#252d3a",
    fg="white"
)

risk_score_label.pack(side="left")


# Display the risk category
risk_level_label = tk.Label(
    risk_frame,
    text="Awaiting Email",
    font=("Arial", 12, "bold"),
    bg="#252d3a",
    fg="#9ca3af"
)

risk_level_label.pack(side="right")


# =====================================
# CREATE THE EMAIL DETAILS AREA
# =====================================

details_frame = tk.LabelFrame(
    root,
    text=" Email Information ",
    font=("Arial", 11, "bold"),
    bg="#151a24",
    fg="white",
    padx=15,
    pady=10
)

details_frame.pack(fill="x", padx=25, pady=10)


# Create labels that we can update after uploading an email
sender_label = tk.Label(
    details_frame,
    text="Sender: Not selected",
    bg="#151a24",
    fg="white",
    anchor="w"
)

sender_label.pack(fill="x", pady=3)


subject_label = tk.Label(
    details_frame,
    text="Subject: Not selected",
    bg="#151a24",
    fg="white",
    anchor="w"
)

subject_label.pack(fill="x", pady=3)


domain_label = tk.Label(
    details_frame,
    text="Sender Domain: Not selected",
    bg="#151a24",
    fg="white",
    anchor="w"
)

domain_label.pack(fill="x", pady=3)


# =====================================
# CREATE THE INVESTIGATION RESULTS AREA
# =====================================

results_frame = tk.LabelFrame(
    root,
    text=" Investigation Results ",
    font=("Arial", 11, "bold"),
    bg="#151a24",
    fg="white",
    padx=10,
    pady=10
)

results_frame.pack(
    fill="both",
    expand=True,
    padx=25,
    pady=10
)


# Create a scrolling text box for investigation results
results = ScrolledText(
    results_frame,
    bg="#202938",
    fg="white",
    insertbackground="white",
    font=("Consolas", 10),
    wrap="word",
    height=15,
    relief="flat"
)

results.pack(fill="both", expand=True)


# =====================================
# EMAIL UPLOAD AND INVESTIGATION
# =====================================

def upload_email():

    # Open File Explorer so the user can select an email
    file_path = filedialog.askopenfilename(
        title="Select an Email File",
        filetypes=[("Email files", "*.eml")]
    )

    # Stop if the user cancels the file selection
    if not file_path:
        return

    try:

        # Open the selected email file
        with open(file_path, "rb") as file:

            sender, receiver, subject, date, message = read_email(file)

        # Analyse the email for suspicious phrases
        found_words = check_suspicious_words(message)

        # Extract website links from the email
        links = extract_links(message)

        # Check the extracted links for warning signs
        suspicious_links = check_suspicious_links(links)

        # Extract the sender's email address and domain
        sender_info = check_sender(sender)

        # Calculate the final risk score
        score, risk = calculate_risk(
            found_words,
            suspicious_links
        )

        # Store all results so they can be exported as a PDF
        global latest_report

        latest_report = {
            "sender": sender or "Unknown",
            "receiver": receiver or "Unknown",
            "subject": subject or "No subject",
            "date": date or "Unknown",
            "sender_domain": sender_info["domain"],
            "suspicious_words": found_words,
            "links": links,
            "suspicious_links": suspicious_links,
            "risk_score": score,
            "risk_level": risk
        }

        # Update the email information labels
        sender_label.config(
            text=f"Sender: {sender or 'Unknown'}"
        )

        subject_label.config(
            text=f"Subject: {subject or 'No subject'}"
        )

        domain_label.config(
            text=f"Sender Domain: {sender_info['domain']}"
        )

        # Update the risk score
        risk_score_label.config(
            text=f"Risk Score: {score}/100"
        )

        # Choose a colour based on the risk category
        if risk == "HIGH":
            risk_colour = "#ef4444"

        elif risk == "MEDIUM":
            risk_colour = "#f59e0b"

        else:
            risk_colour = "#22c55e"

        # Update the risk category and its colour
        risk_level_label.config(
            text=f"RISK LEVEL: {risk}",
            fg=risk_colour
        )

        # Clear any previous investigation results
        results.delete("1.0", tk.END)

        # Display the email message information
        results.insert(tk.END, "========== EMAIL MESSAGE ==========\n\n")
        results.insert(tk.END, message or "No readable message found.")

        # Display suspicious phrases
        results.insert(tk.END, "\n\n========== SUSPICIOUS WORDS ==========\n\n")

        if found_words:
            for word in found_words:
                results.insert(tk.END, f"- {word}\n")
        else:
            results.insert(tk.END, "No suspicious words found.\n")

        # Display all extracted links
        results.insert(tk.END, "\n========== LINKS FOUND ==========\n\n")

        if links:
            for link in links:
                results.insert(tk.END, f"- {link}\n")
        else:
            results.insert(tk.END, "No links found.\n")

        # Display suspicious link warnings
        results.insert(tk.END, "\n========== SUSPICIOUS LINKS ==========\n\n")

        if suspicious_links:
            for link in suspicious_links:
                results.insert(tk.END, f"- {link['url']}\n")
                results.insert(tk.END, f"  Reason: {link['reason']}\n")
        else:
            results.insert(tk.END, "No suspicious link indicators found.\n")

        # Display the final investigation result
        results.insert(tk.END, "\n========== FINAL RISK ASSESSMENT ==========\n\n")
        results.insert(tk.END, f"Risk Score: {score}/100\n")
        results.insert(tk.END, f"Risk Level: {risk}\n")

        results.insert(tk.END, "\n========== INVESTIGATION COMPLETE ==========\n")

    except Exception as error:

        # Show an error if the email could not be investigated
        messagebox.showerror(
            "Investigation Error",
            str(error)
        )


# =====================================
# EXPORT INVESTIGATION AS A PDF
# =====================================

def export_pdf():

    # Check whether an email has been investigated
    if latest_report is None:

        messagebox.showwarning(
            "No Investigation",
            "Please upload and investigate an email first."
        )

        return

    # Ask the user where to save the PDF report
    output_path = filedialog.asksaveasfilename(
        title="Save Investigation Report",
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf")],
        initialfile="phishing_investigation_report.pdf"
    )

    # Stop if the user cancels
    if not output_path:
        return

    try:

        # Generate the PDF using our report generator
        generate_pdf(latest_report, output_path)

        # Tell the user that the report was saved
        messagebox.showinfo(
            "Report Created",
            "Your PDF investigation report was saved successfully."
        )

    except Exception as error:

        # Show an error if PDF creation fails
        messagebox.showerror(
            "PDF Export Error",
            str(error)
        )


# =====================================
# CREATE THE APPLICATION BUTTONS
# =====================================

# Create the green upload button
upload_button = tk.Button(
    button_frame,
    text="UPLOAD EMAIL",
    font=("Arial", 11, "bold"),
    bg="#059669",
    fg="white",
    activebackground="#047857",
    activeforeground="white",
    command=upload_email,
    padx=20,
    pady=10,
    relief="flat",
    cursor="hand2"
)

upload_button.pack(side="left", padx=5)


# Create the blue PDF export button
pdf_button = tk.Button(
    button_frame,
    text="EXPORT PDF REPORT",
    font=("Arial", 11, "bold"),
    bg="#2563eb",
    fg="white",
    activebackground="#1d4ed8",
    activeforeground="white",
    command=export_pdf,
    padx=20,
    pady=10,
    relief="flat",
    cursor="hand2"
)

pdf_button.pack(side="left", padx=5)


# =====================================
# START THE APPLICATION
# =====================================

# Keep the window open and wait for user interaction
root.mainloop()