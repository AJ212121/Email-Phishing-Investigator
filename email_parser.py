 #Import email tools
from email import policy
from email.parser import BytesParser

#Create a function to read email file
def read_email(file):
    #convert email file into a format python understand
    email=BytesParser(policy=policy.default).parse(file)
    #Extract info form email
    sender=email["From"]
    receiver=email["To"]
    subject=email["Subject"]
    date=email["Date"]

    #extract email message
    body=email.get_body(preferencelist=("plain",))

    #Check whether the email has a readable message
    if body:
        message = body.get_content()
    else:
        message="No readable email message found"

    #Return all info
    return sender, receiver, subject, date, message


