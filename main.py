
# Import our email reading function
from email_parser import read_email

# Import our phishing detection functions
from phishing_detector import (
    check_suspicious_words,
    extract_links,
    check_suspicious_links,
    check_sender,
    calculate_risk
)


# Ask the user for an email file
file_path = input("Enter the path of your email file: ")
# Open and read the email
with open(file_path, "rb") as file:
    sender, receiver, subject, date, message = read_email(file)


# Display the extracted email information
print("\n========== EMAIL INFORMATION ==========")
print("Sender:", sender)
print("Receiver:", receiver)
print("Subject:", subject)
print("Date:", date)
print("\n========== EMAIL MESSAGE ==========")
print(message)


# Check for suspicious words
found_words = check_suspicious_words(message)
# Extract links from the email
links = extract_links(message)
# Check the extracted links
suspicious_links = check_suspicious_links(links)
# Extract sender information
sender_info = check_sender(sender)


# Calculate the risk score
score, risk = calculate_risk(
    found_words,
    suspicious_links
)


# Display the investigation results
print("\n========== PHISHING INVESTIGATION ==========")
print("\nSuspicious words found:")

if found_words:

    for word in found_words:
        print("-", word)
else:
    print("No suspicious words found.")
print("\nLinks found:")

if links:
    for link in links:
        print("-", link)
else:
    print("No links found.")
print("\nSuspicious links:")

if suspicious_links:

    for link in suspicious_links:
        print("-", link["url"])
        print("  Reason:", link["reason"])
else:
    print("No suspicious link indicators found.")
print("\nSender domain:", sender_info["domain"])


# Display the final risk assessment
print("\n========== FINAL RISK ASSESSMENT ==========")
print("Risk score:", score, "/ 100")
print("Risk level:", risk)
print("\n========== INVESTIGATION COMPLETE ==========")
