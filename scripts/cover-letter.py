#!/usr/bin/env python3

import sys
import re
import mailbox
import tempfile

def main( arguments ):
    infile_name = arguments[1]

    if infile_name.split('.')[-1] == "eml":
        try:
            fi = open(infile_name, 'r')
        except:
            sys.stderr.write("Error while opening " + infile_name + "\n")
            raise

        tmpfile = tempfile.NamedTemporaryFile(delete=True)
        inbox = mailbox.mbox(tmpfile.name, create=True)
        try:
            inbox.add( fi )
        except:
            inbox.close()
            raise

        fi.close()

    else:
        inbox = mailbox.mbox(infile_name)

    for msg in inbox:
        subject = msg['subject']
        if " 0/" in subject or " 00/" in subject:
            sender = msg['from']
            sender = re.sub(r'<.*>', '', sender)
            print("\n%s says:\n" % sender)
            print("====================\n")
            print("%s" % msg.get_payload())
            print("====================\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: ./cover-letter.py input.mbox\n")
        sys.exit(1)
    sys.exit( main( sys.argv ) )
