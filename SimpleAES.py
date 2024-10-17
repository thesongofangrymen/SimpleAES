#!/usr/bin/env python3
# Requires pycryptodome and windows-curses (on Windows)
import curses
import base64
import hashlib
from Crypto.Cipher import AES
import secrets
import sys
import os
import signal
import tempfile
import subprocess

if os.name == "nt":
    import msvcrt
else:
    import termios


def signal_handler(signum, frame):
    # Do nothing when a signal is received
    pass

def setup_signal_handlers():
    # Set up handlers for various signals
    signals = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, 'SIGTSTP'):
        signals.append(signal.SIGTSTP)
    
    for sig in signals:
        signal.signal(sig, signal_handler)
        if hasattr(signal, 'siginterrupt'):
            signal.siginterrupt(sig, False)


def clear_input_buffer():
    if os.name == "nt":
        while msvcrt.kbhit():
            msvcrt.getch()
    else:
        termios.tcflush(sys.stdin, termios.TCIOFLUSH)


def wait_for_enter():
    if os.name == "nt":
        while True:
            if msvcrt.kbhit() and msvcrt.getch() == b"\r":
                break
    else:
        sys.stdin.read(1)


def open_in_editor(content, prompt, stdscr):
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+", delete=False, suffix=".txt", encoding="utf-8"
        ) as temp:
            temp.write(content)
            temp_file = temp.name

        if sys.platform.startswith("win"):
            os.startfile(temp_file)
        elif sys.platform.startswith("darwin"):
            subprocess.call(("open", temp_file))
        else:
            subprocess.call(("xdg-open", temp_file))

        # Display the message within the curses window itself
        stdscr.clear()
        stdscr.addstr(2, 2, f"{prompt}")
        stdscr.addstr(4, 2, "Press Enter when you're done viewing the file...")
        stdscr.refresh()

        clear_input_buffer()  # Clear any extra keystrokes
        wait_for_enter()  # Wait for the user to press Enter
    finally:
        if os.path.exists(temp_file):
            os.unlink(temp_file)


def get_multiline_input(stdscr, prompt):
    curses.curs_set(0)
    stdscr.clear()
    stdscr.addstr(2, 2, prompt)
    stdscr.addstr(4, 2, "Press any key to open the text editor...")
    stdscr.refresh()
    stdscr.getch()

    with tempfile.NamedTemporaryFile(
        mode="w+", delete=False, suffix=".txt", encoding="utf-8"
    ) as temp:
        temp_filename = temp.name

    if sys.platform.startswith("win"):
        os.startfile(temp_filename)
    elif sys.platform.startswith("darwin"):
        subprocess.call(("open", temp_filename))
    else:
        subprocess.call(("xdg-open", temp_filename))

    stdscr.addstr(2, 2, "Edit the text in the opened editor.")
    stdscr.addstr(4, 2, "Save the file and close the editor when you're done.")
    stdscr.addstr(6, 2, "Then press any key here to continue...")
    stdscr.refresh()
    stdscr.getch()

    with open(temp_filename, "r", encoding="utf-8") as temp:
        content = temp.read()

    os.unlink(temp_filename)
    return content


class AESCrypt:
    def __init__(self, stdscr, opt: str):
        self.stdscr = stdscr
        if opt.lower() == "e":
            plaintext = get_multiline_input(
                stdscr, "Enter plain text for encryption in the text editor:"
            )
            password = self.get_password("Password: ")
            self.result = self.encrypt(plaintext, password)
        elif opt.lower() == "d":
            ciphertext = get_multiline_input(
                stdscr, "Paste the encrypted text in the text editor:"
            )
            password = self.get_password("Password: ")
            self.result = self.decrypt(ciphertext, password)

    def get_password(self, prompt):
        self.stdscr.clear()
        self.stdscr.addstr(2, 2, prompt)
        curses.noecho()  # Turn off character echoing
        curses.curs_set(0)  # Hide the cursor
        password = ""
        while True:
            char = self.stdscr.getch()
            if char == ord("\n"):
                break
            elif char == ord("\b") or char == 127:  # Backspace or Delete
                if password:
                    password = password[:-1]
            elif 32 <= char <= 126:  # Printable characters
                password += chr(char)
        return password

    def encrypt(self, data: str, password: str):
        iv = secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), iv, 600000)
        cipher = AES.new(key, AES.MODE_GCM, iv)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode("utf-8"))
        return base64.urlsafe_b64encode(iv + tag + ciphertext).decode("utf-8")

    def decrypt(self, data: str, password: str):
        try:
            raw = base64.urlsafe_b64decode(data)
            iv, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
            key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), iv, 600000)
            cipher = AES.new(key, AES.MODE_GCM, iv)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode("utf-8")
        except (ValueError, KeyError):
            raise ValueError("Incorrect decryption password")


def main(stdscr):
    # Set up the SIGINT (Ctrl+C) handler
    setup_signal_handlers()

    curses.curs_set(0)
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        title = [
            "           ______  _____ ",
            "     /\\   |  ____|/ ____|",
            "    /  \\  | |__  | (___  ",
            "   / /\\ \\ |  __|  \\___ \\ ",
            "  / ____ \\| |____ ____) |",
            " /_/    \\_\\______|_____/ ",
        ]
        start_row = (h - len(title)) // 2

        for i, line in enumerate(title):
            truncated_line = line[: w - 1]
            start_col = (w - len(truncated_line)) // 2
            stdscr.addstr(start_row + i, start_col, truncated_line)

        stdscr.addstr(h - 2, 2, "_E_ncrypt  or  _D_ecrypt  (Press 'q' to quit)")
        stdscr.refresh()

        option = stdscr.getch()
        if chr(option).lower() == "q":  # Press 'q' to quit
            break

        try:
            if chr(option).lower() in ["e", "d"]:
                result = AESCrypt(stdscr, chr(option)).result
                # No need to exit curses, just pass stdscr to open_in_editor
                open_in_editor(result, "Your message is in the opened file.", stdscr)
        except Exception as e:
            stdscr.addstr(h - 4, 2, f"Error: {str(e)[:w-10]}")
            stdscr.addstr(h - 2, 2, "Press any key to continue...")
            stdscr.refresh()
            stdscr.getch()


if __name__ == "__main__":
    if sys.platform.startswith("win"):
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
        # Windows-specific Ctrl+C handling
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleCtrlHandler(None, True)
    else:
        import locale
        locale.setlocale(locale.LC_ALL, "")
    
    # Set up signal handlers before starting curses
    setup_signal_handlers()
    
    curses.wrapper(main)
