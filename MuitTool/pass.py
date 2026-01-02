import secrets
import string
import secrets
import string
import random
import os

def generate_bulk_passwords(count=100000, min_len=8, max_len=20, filename="Pass.txt", include_common=True, common_file=None, fast=True):

    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    chars = upper + lower + digits

    # A short default list of common passwords (used if no common_file provided)
    COMMON_PASSWORDS = [
        "123456",
        "password",
        "123456789",
        "12345678",
        "12345",
        "qwerty",
        "abc123",
        "football",
        "letmein",
        "iloveyou",
    ]

    # If a common_file is provided and exists, read all lines from it and use them
    common_list = []
    if include_common:
        if common_file and os.path.isfile(common_file):
            try:
                with open(common_file, "r", encoding="utf-8", errors="ignore") as cf:
                    for line in cf:
                        p = line.strip()
                        if p:
                            common_list.append(p)
            except Exception:
                # Fall back to default list if the file can't be read
                common_list = COMMON_PASSWORDS
        else:
            common_list = COMMON_PASSWORDS

    try:
        # Use a set to avoid writing duplicates if a generated password matches a common one
        written = set()
        buffer = []
        buffer_limit = 1000
        with open(filename, "w", encoding="utf-8") as file:
            if include_common and common_list:
                for p in common_list:
                    if p in written:
                        continue
                    buffer.append(p + "\n")
                    written.add(p)
                    if len(buffer) >= buffer_limit:
                        file.writelines(buffer)
                        buffer.clear()

            # Generate random passwords after writing common ones
            generated = 0
            # Fast mode uses `random.choices` and `random.shuffle` for speed
            if fast:
                r = random
                while generated < count:
                    length = r.randint(min_len, max_len)
                    required = [r.choice(upper), r.choice(lower), r.choice(digits)]
                    if length > 3:
                        rest = r.choices(chars, k=length - 3)
                        pwd_chars = required + rest
                    else:
                        pwd_chars = required[:length]
                    r.shuffle(pwd_chars)
                    password = ''.join(pwd_chars)
                    if password in written:
                        continue
                    buffer.append(password + "\n")
                    written.add(password)
                    generated += 1
                    if len(buffer) >= buffer_limit:
                        file.writelines(buffer)
                        buffer.clear()
            else:
                sysrand = random.SystemRandom()
                while generated < count:
                    length = random.randint(min_len, max_len)
                    pwd_chars = [secrets.choice(upper), secrets.choice(lower), secrets.choice(digits)]
                    for _ in range(length - 3):
                        pwd_chars.append(secrets.choice(chars))
                    sysrand.shuffle(pwd_chars)
                    password = ''.join(pwd_chars)
                    if password in written:
                        continue
                    buffer.append(password + "\n")
                    written.add(password)
                    generated += 1
                    if len(buffer) >= buffer_limit:
                        file.writelines(buffer)
                        buffer.clear()

            # flush remaining buffer
            if buffer:
                file.writelines(buffer)

        print(f"Successfully generated {count} passwords in '{filename}'.")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    generate_bulk_passwords()