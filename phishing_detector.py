#import regual expression library
import re

#Import tool to extract email address
from email.utils import parseaddr

#list of word used in phishing emails
suspicious_words= [
    "urgent",
    "verify your account",
    "password",
    "account suspended",
    "click here",
    "bank details",
    "limited time",
    "confirm your identity",
    "payment required"
]

#funtion to check if email has suspicious words
def check_suspicious_words(message):
    #list to store words founnd
    found_words=[]
    #convert email to lowercase 
    message=message.lower()
    #check for suspicious words
    for word in suspicious_words:
        #check if word exists in email and if it does add to matching word list
        if word in message:
            found_words.append(word)
    #return all words found
    return found_words

#funtion to find links in an email
def extract_links(message):
    #pattern for websites addresses
    url_pattern =r'https?://[^\s<>"]+'
    #search email to find matching links
    links=re.findall(url_pattern,message)
    #return found links
    return links

#function to check if url has warnings
def check_suspicious_links(links):
    #lists to store suspicious links
    suspicious_links=[]
    #common url shortener domains
    shorteners= [
        "bit.ly",
        "tinyurl.com",
        "t.co"
    ]
    #check every link
    for link in links:
        #convert link to lowercase
        link=link.lower()
        #check if url starts with http
        if link.startswith("http://"):
            suspicious_links.append({
                "url": link,
                "reason": "Uses unencrypted HTTP"
            })
        #check if url has shorteners
        for shortener in shorteners:
            if shortener in link:
                suspicious_links.append({
                    "url":link,
                    "reason": "Uses a URL shortener"
                })
                break
    #return all suspicious links
    return suspicious_links

#function to extract sender's domain
def check_sender(sender):
    #extract actual email address
    name, address=parseaddr(sender)
    #check if sender has valid looking email address
    if "@" not in address:
        return{
            "address": address,
            "domain": "Unknown",
            "warning": "Sender address could not be parsed"
        }

    #split address to find domain
    domain = address.split("@")[-1].lower()

    #return sender info
    return{
        "address": address,
        "domain": domain,
        "warning": "Check whether this domain belongs to cliamed organisation"
    }

#function to calculate email's risk score
def calculate_risk(found_words,suspicious_links):
    #starts form zero
    score=0
    #add 10 points for every suspicious word
    score+=len(found_words)*10
    #add 15 for each suspicious link
    score+=len(suspicious_links)*15
    #Max score is 100
    score=min(score,100)

    #deciding risk category
    if score >= 60:
        risk= "HIGH"
    elif score >= 30:
        risk="Medium"
    else:
        risk="LOW"
    #return score and category
    return score, risk