#!/usr/bin/env python3
"""
Account helper for the Medical Advisors Hub.

Generates the bcrypt hash for an advisor's password and prints a JSON entry you
paste into the ADVISOR_ACCOUNTS environment variable (locally in .env, and in
the Render dashboard for production).

Usage:
    python make_hash.py                      # interactive (password hidden)
    python make_hash.py advisor@example.com  # prompts for password only

Then add the printed line to ADVISOR_ACCOUNTS, e.g.:
    ADVISOR_ACCOUNTS={"advisor@example.com": "$2b$12$...."}
Multiple advisors go in the same JSON object, comma-separated.
"""

import getpass
import json
import sys

import bcrypt


def main():
    if len(sys.argv) > 1:
        email = sys.argv[1].strip().lower()
    else:
        email = input("Advisor email: ").strip().lower()

    if not email or "@" not in email:
        print("Please provide a valid email address.")
        sys.exit(1)

    pw1 = getpass.getpass("Password: ")
    pw2 = getpass.getpass("Confirm password: ")
    if pw1 != pw2:
        print("Passwords do not match.")
        sys.exit(1)
    if len(pw1) < 8:
        print("Password must be at least 8 characters.")
        sys.exit(1)

    hashed = bcrypt.hashpw(pw1.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    print("\n--- Add this entry to ADVISOR_ACCOUNTS ---")
    print(json.dumps({email: hashed}))
    print(
        "\nIf ADVISOR_ACCOUNTS already has advisors, merge this key into the "
        "existing JSON object rather than replacing it."
    )


if __name__ == "__main__":
    main()
