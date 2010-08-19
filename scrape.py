#!/usr/bin/env python

import logging
import optparse
import os
import imaplib
import email

from getpass import getpass

from lxml import html
from lxml.cssselect import CSSSelector as css

logger = logging.getLogger(__name__)

READ_ONLY = True


def process_html(text):
    tree = html.fromstring(text)
    for img in css("img")(tree):
        src = img.get("src")
        print "src: %s" % src
#        import ipdb; ipdb.set_trace()


def process_message(message_data):
    for response_part in message_data:
        if isinstance(response_part, tuple):
            msg = email.message_from_string(response_part[1])
            if msg.is_multipart():
                for payload in msg.get_payload():
                    print ("Found payload of type: %s" %
                           payload.get_content_type())
                    if payload.get_content_type() == "text/html":
                        process_html(payload.as_string())
            else:
                print "Skipping non-MP message."


def fetch_and_process_message(conn, message_id):
    result, message = conn.fetch(message_id, "(RFC822)")
    if result == "OK":
        process_message(message)
    else:
        print "Error reading message ID: %s" % message_id


def extract_images(email, password, output_directory, mailbox, debug=False):
    # We assume output_directory exists as a check was done in main
    conn = imaplib.IMAP4_SSL("imap.gmail.com")
    if debug:
        conn.debug = 4 # > 3 gets you trace
    conn.login(email, password)
    conn.select(mailbox, READ_ONLY)
    result, data = conn.search(None, 'ALL')
    if result != "OK":
        raise Exception("Expected 'OK' but got: '%s'" % result)
    message_ids = set()
    for datum in data:
        for message_id in datum.split(" "):
            fetch_and_process_message(conn, message_id)
    conn.logout()


def main():
    parser = optparse.OptionParser()
    parser.add_option("-e", "--email")
    parser.add_option("-p", "--password")
    parser.add_option("-o", "--output-directory", default="/tmp/gmail-images")
    parser.add_option("-m", "--mailbox", default="INBOX")
    parser.add_option("-d", "--debug",
                      help="debug mode.  warning, will display password"
                      " in plaintext!",
                      action="store_true")
    options, args = parser.parse_args()

    email = options.email
    password = options.password

    if not email:
        email = raw_input("Enter email address: ")

    if "@" not in email:
        print "No domain specified in email address: assuming gmail.com."
        email = email + "@gmail.com"

    if not password:
        password = getpass("Enter password: ")

    if not os.path.exists(options.output_directory):
        parser.error("Output directory does not exist: %s" %
                     options.output_directory)

    extract_images(email,
                   password,
                   options.output_directory,
                   options.mailbox,
                   options.debug)


if __name__ == '__main__':
    main()
