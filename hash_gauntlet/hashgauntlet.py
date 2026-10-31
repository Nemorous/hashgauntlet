#!/usr/bin/env python3
"""
HashGauntlet - Active Directory credential auditing for blue and purple teams.

Runs a domain's NTLM hashes through a staged gauntlet of dictionary, rule, and
mask attacks, then reports which accounts fell and how quickly, tiered by
severity with remediation windows and an optional encrypted audit log.

Built on Hashcat. Part of the Knight Light toolkit.
Version 3.0.0
"""

import argparse
import textwrap
import os
import subprocess
import sys
import time
import itertools
import tempfile
import signal
import shutil
import atexit
import threading
import select
import platform
import gc
import getpass
import hashlib
import json
import secrets
from pathlib import Path
from datetime import datetime
from itertools import product
from collections import deque, defaultdict

# Rich library for persistent status bar
try:
    from rich.live import Live
    from rich.console import Console, Group
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# AES-256-GCM encryption for audit log
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# Mask character set sizes for calculation
MASK_SIZES = {
    '?d': 10,   # digits 0-9
    '?l': 26,   # lowercase a-z
    '?u': 26,   # uppercase A-Z
    '?s': 33,   # special chars
    '?a': 95    # all printable
}

# Mask priority order (most common first)
MASK_PRIORITY = ['?d', '?s', '?l', '?u', '?a']

# Hashcat optimized kernel password length limits
# When using -O flag, passwords exceeding these limits are skipped
OPTIMIZED_LIMITS = {
    500: 15,    # md5crypt, MD5(Unix), FreeBSD MD5, Cisco-IOS MD5
    1800: 15,   # sha512crypt, SHA512(Unix)
    3200: 55,   # bcrypt, Blowfish(OpenBSD)
    7400: 15,   # sha256crypt, SHA256(Unix)
    1000: 27,   # NTLM
    3000: 7,    # LM
    0: 31,      # MD5
    100: 31,    # SHA1
    1400: 31,   # SHA256
    1700: 15,   # SHA512
    2500: 63,   # WPA/WPA2
    16800: 63,  # WPA-PMKID-PBKDF2
}

# Cyan ANSI color + newline
CYAN = '\033[38;5;117m'
RESET = '\033[0m'

# ANSI escape codes for persistent status bar
SAVE_CURSOR = '\033[s'
RESTORE_CURSOR = '\033[u'
CLEAR_LINE = '\033[2K'
MOVE_TO_COL_0 = '\r'
HIDE_CURSOR = '\033[?25l'
SHOW_CURSOR = '\033[?25h'

# Global list to track temporary files for cleanup
_temp_files = []

# Global path to track intermediates directory for cleanup
_intermediates_dir = None

# Rich components for persistent status bar
_rich_live = None
_rich_console = None

# Quiet mode flag
_quiet_mode = False

# No-leet mode flag
_no_leet = False

# Per-hash crack timestamps: {ntlm_hash: unix_timestamp_when_cracked}
_crack_timestamps = {}

# Hash-to-username mapping from secretsdump: {ntlm_hash: SAMAccountName}
_hash_to_user = {}

# Session start time for severity classification
_session_start_time = None

# Cache for pre-split wordlists by character length
# Structure: {wordlist_path: {max_length: {'within': path, 'over': path}}}
_presplit_wordlist_cache = {}

def get_optimal_temp_dir():
    """
    Get best temp directory for intermediate files (cross-platform)

    Linux: Prefers /dev/shm (RAM) if available with 100MB+ free, else system temp
    Windows: Uses %TEMP% (Windows auto-caches small files in RAM)
    macOS: Uses /tmp (macOS has automatic RAM caching)

    Returns:
        str: Path to optimal temporary directory
    """
    system = platform.system()

    if system == 'Linux':
        # Check if /dev/shm exists and is writable
        if os.path.exists('/dev/shm') and os.access('/dev/shm', os.W_OK):
            try:
                # Check available space (require at least 100MB free)
                stat = shutil.disk_usage('/dev/shm')
                if stat.free > 100 * 1024 * 1024:  # 100MB in bytes
                    return '/dev/shm'
            except Exception:
                pass  # Fall through to system temp
        return tempfile.gettempdir()

    elif system == 'Windows':
        # Windows %TEMP% directory
        return tempfile.gettempdir()

    else:  # macOS, BSD, etc.
        # Unix-like systems use /tmp with automatic caching
        return tempfile.gettempdir()

def get_available_disk_space(directory):
    """
    Get available disk space for a directory in bytes

    Args:
        directory: Path to check disk space for

    Returns:
        int: Available space in bytes, or 0 if unable to determine
    """
    try:
        stat = shutil.disk_usage(directory)
        return stat.free
    except Exception:
        return 0

def estimate_intermediate_size(base_wordlist, wordlist_suffix=''):
    """
    Estimate total disk space needed for all 11 intermediate wordlists

    Args:
        base_wordlist: Path to the base wordlist file
        wordlist_suffix: Optional suffix for intermediate files (e.g., '_leet')

    Returns:
        float: Estimated total size in bytes, or -1 if unable to estimate
    """
    try:
        # Sample base wordlist to get average word length
        sample_words = []
        with open(base_wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= 1000:
                    break
                sample_words.append(line.strip())

        if not sample_words:
            return -1

        avg_word_len = sum(len(w) for w in sample_words) / len(sample_words)
        total_words = count_wordlist_lines(base_wordlist)

        # Define the 11 intermediates with their multiplication factors
        # Format: (mask, multiplier) where multiplier = combinations
        intermediates = [
            ('?d', 10),          # d_prepend or d_append
            ('?d?d', 100),       # dd_prepend or dd_append
            ('?d?s', 330),       # ds_prepend or ds_append
            ('?s', 33),          # s_prepend or s_append
            ('?s?s', 1089),      # ss_prepend
            ('?s?d', 330),       # sd_prepend or sd_append
            ('?d', 10),          # d_append (separate file from d_prepend)
            ('?d?d', 100),       # dd_append (separate file from dd_prepend)
            ('?d?s', 330),       # ds_append (separate file from ds_prepend)
            ('?s', 33),          # s_append (separate file from s_prepend)
            ('?s?d', 330),       # sd_append (separate file from sd_prepend)
        ]

        total_size = 0
        for mask, multiplier in intermediates:
            # Calculate mask length (each ?X is 2 chars in mask notation = 1 actual char)
            mask_len = len(mask.replace('?', '')) // 2
            # Average line length = mask_len + avg_word_len + 1 (newline)
            avg_line_len = mask_len + avg_word_len + 1
            # Total lines = wordlist lines * combinations
            total_lines = total_words * multiplier
            # Total bytes for this intermediate
            intermediate_bytes = total_lines * avg_line_len
            total_size += intermediate_bytes

        return total_size

    except Exception:
        return -1


def create_status_bar_text():
    """Create the status bar text using Rich"""
    global _session_control, _no_leet
    # Cyan color (matches ANSI color 117)
    cyan = "color(117)"

    status_text = Text()

    # Only show [s]tatus if hashcat has displayed status at least once
    if _session_control.is_status_available():
        status_text.append("[s]", style=f"{cyan}")
        status_text.append("tatus ")

    status_text.append("[p]", style=f"{cyan}")
    status_text.append("ause ")
    status_text.append("[r]", style=f"{cyan}")
    status_text.append("esume ")
    status_text.append("[n]", style=f"{cyan}")
    status_text.append("ext ")
    status_text.append("[f]", style=f"{cyan}")
    status_text.append("inish ")
    status_text.append("[k]", style=f"{cyan}")
    status_text.append("ill")

    return status_text

def setup_status_bar():
    """Setup persistent status bar at bottom using Rich"""
    global _rich_live, _rich_console, _quiet_mode, _no_leet

    # Don't setup status bar in quiet mode
    if _quiet_mode:
        return

    # Only setup if stdout is TTY and Rich is available
    if not sys.stdout.isatty() or not RICH_AVAILABLE:
        # Fallback: just print it - prepend [s]tatus if available
        global _session_control
        status_str = ""
        if _session_control.is_status_available():
            status_str = "[s]tatus "
        status_str += "[p]ause [r]esume [n]ext "
        status_str += "[f]inish [k]ill"
        print(f"\n{CYAN}{status_str}{RESET}\n", flush=True)
        return

    # Create Rich console and live display with newline above status bar
    _rich_console = Console()
    status_display = Group(
        "",  # Blank line above the status bar
        create_status_bar_text()
    )
    _rich_live = Live(
        status_display,
        console=_rich_console,
        refresh_per_second=4,
        transient=False
    )
    _rich_live.start()

def cleanup_status_bar():
    """Stop Rich live display"""
    global _rich_live

    if _rich_live:
        try:
            _rich_live.stop()
        except:
            pass
        _rich_live = None

# Session control flags for interactive keyboard commands
class SessionControl:
    """Thread-safe control flags for managing HashGauntlet session"""
    def __init__(self):
        self.lock = threading.Lock()
        self.skip_to_next = False      # [n]ext - skip current attack
        self.finish_session = False    # [f]inish - complete current then stop
        self.kill_all = False          # [k]ill - stop everything immediately
        self.paused = False            # [p]ause - pause current attack
        self.hashcat_process = None    # Current hashcat process
        self.prompt_shown = False      # Track if interactive prompt has been shown
        self.show_status = False       # Track if status display was requested
        self.status_available = False  # Track if hashcat has shown status at least once

    def reset_attack_flags(self):
        """Reset flags that apply only to current attack"""
        with self.lock:
            self.skip_to_next = False
            self.paused = False
            self.status_available = False  # Reset status availability for new attack

    def set_skip_next(self):
        with self.lock:
            self.skip_to_next = True

    def set_finish(self):
        with self.lock:
            self.finish_session = True

    def set_kill(self):
        with self.lock:
            self.kill_all = True

    def toggle_pause(self):
        with self.lock:
            self.paused = not self.paused
            return self.paused

    def should_skip(self):
        with self.lock:
            return self.skip_to_next

    def should_finish(self):
        with self.lock:
            return self.finish_session

    def should_kill(self):
        with self.lock:
            return self.kill_all

    def is_paused(self):
        with self.lock:
            return self.paused

    def set_process(self, process):
        with self.lock:
            self.hashcat_process = process

    def get_process(self):
        with self.lock:
            return self.hashcat_process

    def request_status(self):
        """Request status display"""
        with self.lock:
            self.show_status = True

    def should_show_status(self):
        """Check if status should be displayed"""
        with self.lock:
            return self.show_status

    def clear_status_request(self):
        """Clear status display request"""
        with self.lock:
            self.show_status = False

    def mark_status_available(self):
        """Mark that hashcat status is now available"""
        with self.lock:
            self.status_available = True

    def is_status_available(self):
        """Check if hashcat status is available"""
        with self.lock:
            return self.status_available

    def reset_status_availability(self):
        """Reset status availability for new attack"""
        with self.lock:
            self.status_available = False

# Global session control instance
_session_control = SessionControl()

# Global terminal settings for cleanup
_terminal_settings = None

def cleanup_temp_files():
    """Clean up temporary files and intermediates directory on exit or interrupt"""
    global _temp_files, _intermediates_dir

    # Make a copy to avoid issues if list is modified during iteration
    files_to_clean = list(_temp_files)
    for temp_file in files_to_clean:
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except Exception:
            pass  # Silently fail on cleanup
    # Clear the list after cleanup attempt
    _temp_files.clear()

    # Clean up intermediates directory and parent wordlists directory in temp
    if _intermediates_dir and os.path.exists(_intermediates_dir):
        try:
            # Remove intermediates directory
            shutil.rmtree(_intermediates_dir)
            # Also remove parent wordlists directory if it's in temp and now empty
            wordlists_parent = os.path.dirname(_intermediates_dir)
            if os.path.exists(wordlists_parent) and not os.listdir(wordlists_parent):
                os.rmdir(wordlists_parent)
        except Exception:
            pass  # Silently fail on cleanup

def signal_handler(sig, frame):
    """Handle Ctrl+C and other signals gracefully"""
    global _terminal_settings, _session_control

    try:
        # Kill any running hashcat process first
        process = _session_control.get_process()
        if process and process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=0.5)
            except:
                pass

        # Restore terminal settings if they were saved
        if _terminal_settings is not None:
            try:
                import termios
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, _terminal_settings)
            except:
                pass

        cleanup_status_bar()
        print(f"\n{CYAN}[!] Interrupted by user...{RESET}", flush=True)
        cleanup_temp_files()
        print(f"{CYAN}[!] HashGauntlet session terminated{RESET}", flush=True)

        # Clean exit (no shell "killed" message)
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(1)
    except Exception:
        # If anything fails, force exit anyway
        os.kill(os.getpid(), signal.SIGKILL)

# Register cleanup handlers
atexit.register(cleanup_temp_files)
signal.signal(signal.SIGINT, signal_handler)

# SIGTERM is not available on Windows - register only on Unix/Linux
if hasattr(signal, 'SIGTERM'):
    signal.signal(signal.SIGTERM, signal_handler)


def show_interactive_prompt():
    """Display the interactive keyboard controls prompt"""
    global _session_control
    if not _session_control.prompt_shown:
        setup_status_bar()
        _session_control.prompt_shown = True


def keyboard_monitor_thread():
    """
    Monitor keyboard input in a background thread.
    Handles HashGauntlet-level commands and passes hashcat commands through.
    """
    global _session_control, _quiet_mode

    # Don't start keyboard monitor in quiet mode
    if _quiet_mode:
        return

    # Set up signal handling to interrupt select()
    if sys.platform != 'win32':
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})

    # Only run keyboard monitor if stdin is a TTY (interactive terminal)
    if not sys.stdin.isatty():
        return

    # Platform-specific keyboard handling
    if sys.platform == 'win32':
        # Windows keyboard handling using Console API (hashcat-style)
        import msvcrt
        import ctypes
        from ctypes import wintypes

        # Windows Console API constants
        STD_INPUT_HANDLE = -10
        WAIT_OBJECT_0 = 0
        WAIT_TIMEOUT = 0x00000102

        # Get console input handle
        kernel32 = ctypes.windll.kernel32
        hStdin = kernel32.GetStdHandle(STD_INPUT_HANDLE)

        while True:
            # Wait for input with 100ms timeout (hashcat uses 1000ms, we use less for responsiveness)
            result = kernel32.WaitForSingleObject(hStdin, 100)

            if result == WAIT_OBJECT_0:
                # Input is available
                if msvcrt.kbhit():
                    key = msvcrt.getch()

                    # Handle special keys (arrow keys, function keys, etc.) on Windows
                    # Arrow keys send two bytes: 0xE0 (or 0x00) followed by a scan code
                    if key in (b'\xe0', b'\x00'):
                        # Read and discard the second byte (scan code)
                        if msvcrt.kbhit():
                            msvcrt.getch()
                        # Flush any additional input to prevent buffering issues
                        kernel32.FlushConsoleInputBuffer(hStdin)
                        continue  # Skip processing arrow keys and other special keys

                    # Flush any additional input to prevent buffering issues
                    kernel32.FlushConsoleInputBuffer(hStdin)

                    # Check for Ctrl+C (ASCII 3) - exit immediately
                    if key == b'\x03':
                        cleanup_status_bar()
                        print(f"\n{CYAN}[!] Interrupted by user...{RESET}", flush=True)
                        cleanup_temp_files()
                        print(f"{CYAN}[!] HashGauntlet session terminated{RESET}", flush=True)
                        sys.stdout.flush()
                        sys.stderr.flush()
                        os._exit(1)
                    else:
                        try:
                            key = key.decode('utf-8', errors='ignore').lower()
                            handle_keyboard_input(key)
                        except:
                            pass
            # No sleep needed - WaitForSingleObject handles timing
    else:
        # Unix/Linux keyboard handling (non-blocking)
        import tty
        import termios
        global _terminal_settings

        try:
            old_settings = termios.tcgetattr(sys.stdin)
            _terminal_settings = old_settings  # Save globally for signal handler
            tty.setcbreak(sys.stdin.fileno())
            while True:
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    key = sys.stdin.read(1)
                    # Check for Ctrl+C (ASCII 3) - exit immediately
                    if key == '\x03':
                        try:
                            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
                        except:
                            pass
                        cleanup_status_bar()
                        print(f"\n{CYAN}[!] Interrupted by user...{RESET}", flush=True)
                        cleanup_temp_files()
                        print(f"{CYAN}[!] HashGauntlet session terminated{RESET}", flush=True)
                        sys.stdout.flush()
                        sys.stderr.flush()
                        os._exit(1)
                    else:
                        key = key.lower()
                        handle_keyboard_input(key)
        except termios.error:
            # Terminal doesn't support required operations
            return
        finally:
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            except:
                pass


def handle_keyboard_input(key):
    """
    Handle keyboard input for interactive controls.

    [s]tatus - Pass to hashcat (show status)
    [p]ause - Pause hashcat and HashGauntlet session
    [r]esume - Resume hashcat and HashGauntlet session
    [n]ext - HashGauntlet: skip to next attack
    [f]inish - HashGauntlet: finish current attack then stop
    [k]ill - HashGauntlet: kill everything
    """
    global _session_control, _no_leet

    process = _session_control.get_process()

    if key == 's':
        # Status - pass to hashcat and request capture
        _session_control.request_status()
        if process and process.poll() is None:
            try:
                if sys.platform == 'win32':
                    process.stdin.write(b's')
                else:
                    process.stdin.write('s')
                process.stdin.flush()
            except:
                pass

    elif key == 'p':
        # Pause - pass to hashcat AND set HashGauntlet pause flag
        if not _session_control.is_paused():
            if process and process.poll() is None:
                try:
                    if sys.platform == 'win32':
                        process.stdin.write(b'p')
                    else:
                        process.stdin.write('p')
                    process.stdin.flush()
                except:
                    pass
            _session_control.lock.acquire()
            _session_control.paused = True
            _session_control.lock.release()
            print(f"\n{CYAN}[!] HashGauntlet session paused{RESET}\n")

    elif key == 'r':
        # Resume - pass to hashcat AND clear HashGauntlet pause flag
        if _session_control.is_paused():
            if process and process.poll() is None:
                try:
                    if sys.platform == 'win32':
                        process.stdin.write(b'r')
                    else:
                        process.stdin.write('r')
                    process.stdin.flush()
                except:
                    pass
            _session_control.lock.acquire()
            _session_control.paused = False
            _session_control.lock.release()
            print(f"{CYAN}[!] HashGauntlet session resumed{RESET}\n")

    elif key == 'n':
        # Next - skip to next attack
        _session_control.set_skip_next()
        print(f"\n{CYAN}[!] Skipping to next attack...{RESET}\n")
        if process and process.poll() is None:
            try:
                process.terminate()
            except:
                pass

    elif key == 'f':
        # Finish - complete current attack then stop session
        _session_control.set_finish()
        print(f"\n{CYAN}[!] Finishing session after current attack{RESET}\n")

    elif key == 'k':
        # Kill - stop everything immediately
        _session_control.set_kill()

        if process and process.poll() is None:
            try:
                process.kill()
            except:
                pass


def start_keyboard_monitor():
    """Start the keyboard monitoring thread"""
    monitor_thread = threading.Thread(target=keyboard_monitor_thread, daemon=True)
    monitor_thread.start()


class LeadingBlankLineMixin:
    """Insert a blank line before the generated 'usage:' line."""
    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None:
            prefix = "usage: "
        return super().add_usage(usage, actions, groups, prefix="\n" + prefix)

class HelpFormatter(LeadingBlankLineMixin, argparse.RawDescriptionHelpFormatter):
    """
    Aligned, wide help with NO metavars shown for any arguments.
    """
    def __init__(self, prog):
        super().__init__(prog, max_help_position=30, width=100)
    def add_usage(self, usage, actions, groups, prefix=None):
        # Capitalized prefix + leading blank line
        return super().add_usage(usage, actions, groups, prefix="\nUsage: ")
    def _format_action_invocation(self, action):
        # Hide metavars for ALL args (both optionals and positionals).
        if action.option_strings:
            # Show only the flags, e.g. "-f, --hash-file"
            return ", ".join(action.option_strings)
        else:
            # Positional: show just the name without angle brackets/metavar
            return action.dest

    def _format_action(self, action):
        # Force help text to start at a fixed position for better alignment
        help_position = 28  # Adjust this value to change spacing between options and descriptions
        help_width = self._width - help_position

        # Get action invocation string
        action_header = self._format_action_invocation(action)

        # Get help text
        help_text = self._expand_help(action) if action.help else ''

        # Format the action with forced spacing
        if not help_text:
            return f"  {action_header}\n"

        # Calculate padding needed
        action_width = help_position - 2  # -2 for initial indent
        if len(action_header) <= action_width - 2:
            # Action fits on same line as help
            return f"  {action_header:<{action_width-2}}  {help_text}\n"
        else:
            # Action is too long, put help on next line
            return f"  {action_header}\n{' ' * help_position}{help_text}\n"

# --- CLI ---------------------------------------------------------------------

class DescFirstArgumentParser(argparse.ArgumentParser):
    def format_help(self):
        formatter = self._get_formatter()

        # 1) Description (first)
        if self.description:
            formatter.add_text(self.description)
            formatter.add_text("")  # blank line

        # 2) Usage (capitalized)
        formatter.add_usage(self.usage, self._actions,
                            self._mutually_exclusive_groups,
                            prefix="Usage: ")

        formatter.add_text("")  # blank line

        # 3) Argument groups (in declared order)
        for action_group in self._action_groups:
            formatter.start_section(action_group.title)
            formatter.add_arguments(action_group._group_actions)
            formatter.end_section()

        # 4) Epilog (if any)
        if self.epilog:
            formatter.add_text(self.epilog)

        return formatter.format_help()

    # 👇 Add this to fully control the single error line
    def error(self, message):
        # You can style/word this however you like:
        sys.stderr.write(
            f"\n{CYAN}[!] Error:{RESET} {message}\n\n"
        )
        # Optionally also show the full help instead of just the hint:
        self.print_help()
        self.exit(2)

# --- Your parse_args using the custom parser/formatter -----------------------
if ('--help' in sys.argv or '-h' in sys.argv):
    _banner = """
\033[0;37m    \033[0;36m▄\033[0;96;46m▒\033[0;96;47m▄\033[0;36m█▀▀▀\033[0;96;46m▀▄▄\033[0;36m▄\033[0;96;46m▓\033[0;37m      \033[0;36m▄\033[0;96;46m▒\033[0;96;47m▄\033[0;36m█▀▀▀\033[0;96;46m▀▄▄\033[0;36m▄\033[0;96;46m▓\033[0;37m    \033[0;96;46m▓\033[0;97;46m█\033[0;96;46m▄▒░\033[0;37m     \033[0;36m█\033[0;96;46m▄▄░\033[0;36m█\033[0;37m   \033[0;96;46m▓\033[0;36m▄\033[0;96;46m▄▄▀\033[0;36m▀▀▀█\033[0;96;47m▄\033[0;96;46m▒\033[0;36m▄\033[0;37m      \033[0;96;46m▒▄\033[0;97;46m█\033[0;96;46m▄░\033[0;37m    \033[0;36m█\033[0;96;46m█▄▄\033[0;37m     \033[0;96;46m▒▄\033[0;97;46m█\033[0;96;46m▄░\033[0;37m             \033[0;96;46m▓\033[0;36m▄\033[0;96;46m▄▄▀\033[0;36m▀▀▀▀▄\033[0;96;46m▒\033[0;36m▄\033[0;37m     \033[0;96;46m▒▄\033[0;97;46m█\033[0;96;46m▄░\033[0;37m    \033[0;36m█\033[0;96;46m█▄▄\033[0;37m   \033[0m
\033[0;37m  \033[0;96m▄\033[0;96;46m▄█▓░\033[0;37m    \033[0;36m█\033[0;96;46m▒▄▒▄\033[0;37m    \033[0;96m▄\033[0;96;46m▄█▓░\033[0;37m    \033[0;36m█\033[0;96;46m▒▄▒▄\033[0;37m    \033[0;96;46m▓\033[0;36m▀▀\033[0;96;46m▀\033[0;36m█\033[0;37m     \033[0;96;46m░\033[0;36m▀▀\033[0;96;46m▀▒\033[0;37m   \033[0;96;46m▄▒▄▒\033[0;36m█\033[0;37m    \033[0;96;46m░▓█▄\033[0;96m▄\033[0;37m   \033[0;36m▐\033[0;96;46m▀\033[0;36m▀▀\033[0;96;46m▓\033[0;36m█▄▄▄█\033[0;96;46m▓\033[0;97;46m██\033[0;96;46m█\033[0;36m▌\033[0;37m    \033[0;96;46m▀\033[0;36m▀▀\033[0;96;46m▓\033[0;36m█\033[0;37m     \033[0;36m▄\033[0;37m \033[0;36m▀\033[0;37m     \033[0;96;46m▄▒▄▒\033[0;36m█\033[0;37m     \033[0;36m█\033[0;96;46m█▄▄\033[0;37m  \033[0;36m▐\033[0;96;46m▀\033[0;36m▀▀\033[0;96;46m▓\033[0;36m█▄▄▄█\033[0;96;46m▓\033[0;97;46m██\033[0;96;46m█\033[0;36m▌\033[0;37m  \033[0m
\033[0;37m \033[0;36m▐\033[0;96;46m█\033[0;97;46m██\033[0;96;46m▓\033[0;36m▌\033[0;37m    \033[0;96;46m▐▓\033[0;97;46m█\033[0;96;46m█\033[0;36m█\033[0;37m   \033[0;36m▐\033[0;96;46m█\033[0;97;46m██\033[0;96;46m▓\033[0;36m▌\033[0;37m    \033[0;96;46m▐▓\033[0;97;46m█\033[0;96;46m█\033[0;36m█\033[0;37m    \033[0;96;46m▄\033[0;36m▄▄\033[0;96;46m▒\033[0;36m█\033[0;37m     \033[0;96;46m▀▄▄▒\033[0;36m█\033[0;37m   \033[0;36m█\033[0;96;46m█\033[0;97;46m█\033[0;96;46m▓▌\033[0;37m    \033[0;36m▐\033[0;96;46m▓\033[0;97;46m██\033[0;96;46m█\033[0;36m▌\033[0;37m \033[0;36m▄▀\033[0;96;46m░\033[0;36m▀▀\033[0;96;46m▀\033[0;36m█▌▄\033[0;37m \033[0;36m▀\033[0;96;46m▀▀▀░\033[0;37m     \033[0;96;46m░\033[0;36m▀▀\033[0;96;46m▀\033[0;36m█\033[0;37m    \033[0;36m▐▌\033[0;37m       \033[0;36m█\033[0;96;46m█\033[0;97;46m█\033[0;96;46m▓▌\033[0;36m▌\033[0;37m    \033[0;96;46m▓\033[0;97;46m██\033[0;96;46m█\033[0;36m▌▄▀\033[0;96;46m░\033[0;36m▀▀\033[0;96;46m▀\033[0;36m█▌▄\033[0;37m \033[0;36m▀\033[0;96;46m▀▀▀░\033[0;37m   \033[0m
\033[0;37m \033[0;96;46m░▓▀▒░\033[0;37m     \033[0;96;46m ▒\033[0;36m▀▀\033[0;96;46m░\033[0;37m   \033[0;96;46m░▓▀▒░\033[0;37m     \033[0;96;46m ▒\033[0;36m▀▀\033[0;96;46m░\033[0;37m    \033[0;96;46m░\033[0;37m  \033[0;96;46m ░\033[0;37m     \033[0;96;46m▒▀\033[0;97;46m█\033[0;96;46m▄░\033[0;37m   \033[0;96;46m░\033[0;36m▀▀\033[0;96;46m▒ \033[0;37m     \033[0;96;46m░▒▀▓░\033[0;37m   \033[0;96;46m▀\033[0;36m▀▀\033[0;96;46m▀░\033[0;37m \033[0;36m■\033[0;37m    \033[0;36m▄\033[0;37m      \033[0;96;46m▀\033[0;36m▀▀\033[0;96;46m▀░\033[0;37m     \033[0;96;46m░\033[0;36m▄\033[0;37m      \033[0;96;46m░\033[0;36m▀▀\033[0;96;46m▒ \033[0;36m▄▄▄▄█\033[0;96;46m▀▀▀░\033[0;37m   \033[0;96;46m▀\033[0;36m▀▀\033[0;96;46m▀░\033[0;37m \033[0;36m■\033[0;37m    \033[0;36m▄\033[0;37m    \033[0m
\033[0;36m▐\033[0;96;46m░█▓░\033[0;36m▌\033[0;37m     \033[0;36m█\033[0;96;46m▄\033[0;36m▄▄\033[0;96;46m▄\033[0;37m  \033[0;36m▐\033[0;96;46m░█▓░\033[0;36m▌\033[0;37m     \033[0;36m█\033[0;96;46m▄\033[0;36m▄▄\033[0;96;46m▄\033[0;37m    \033[0;96;46m▀▄░█░\033[0;37m     \033[0;36m█\033[0;37m  \033[0;36m█▄\033[0;37m   \033[0;96;46m▄\033[0;36m▄▄\033[0;96;46m▄\033[0;36m█\033[0;37m     \033[0;36m▐\033[0;96;46m░▓█░\033[0;36m▌\033[0;37m  \033[0;96;46m▒\033[0;37m  \033[0;96;46m▒▒\033[0;37m     \033[0;36m▐\033[0;96;46m░▓▄\033[0;36m▄\033[0;37m   \033[0;96;46m▒\033[0;37m  \033[0;96;46m▒▒\033[0;37m     \033[0;36m▐\033[0;96;46m░▓▄\033[0;36m▄\033[0;37m   \033[0;96;46m▄\033[0;36m▄▄\033[0;96;46m▄\033[0;36m█\033[0;37m    \033[0;36m▄\033[0;37m       \033[0;96;46m▒\033[0;37m  \033[0;96;46m▒▒\033[0;37m     \033[0;36m▐\033[0;96;46m░▓▄\033[0;36m▄\033[0;37m \033[0m
\033[0;37m \033[0;96;46m▒██▓\033[0;36m▌\033[0;37m     \033[0;36m█\033[0;96;46m░\033[0;37m  \033[0;96;46m▒\033[0;37m   \033[0;96;46m▒██▓\033[0;36m▌\033[0;37m     \033[0;36m█\033[0;96;46m░\033[0;37m  \033[0;96;46m▒\033[0;37m    \033[0;96;46m▒\033[0;97;46m██\033[0;96;46m█░\033[0;37m     \033[0;96;46m█░░█░\033[0;36m▌\033[0;37m  \033[0;96;46m▒\033[0;37m  \033[0;96;46m░\033[0;36m█\033[0;37m     \033[0;36m▐\033[0;96;46m▓██▒\033[0;36m▌\033[0;37m  \033[0;96;46m▀▄\033[0;97;46m█\033[0;96;46m▓▓\033[0;37m     \033[0;36m█\033[0;96;46m▓██▒\033[0;36m▌\033[0;37m  \033[0;96;46m▀▄\033[0;97;46m█\033[0;96;46m▓▓\033[0;37m     \033[0;36m█\033[0;96;46m▓██▒\033[0;36m▌\033[0;37m  \033[0;96;46m▒\033[0;37m  \033[0;96;46m░\033[0;36m█\033[0;37m     \033[0;96;46m▓▄\033[0;36m▄▄\033[0;37m   \033[0;96;46m▀▄\033[0;97;46m█\033[0;96;46m▓▓\033[0;37m     \033[0;36m█\033[0;96;46m▓██▒\033[0;36m▌\033[0m
\033[0;37m \033[0;36m▐\033[0;96;46m▀\033[0;97;46m█\033[0;96;46m█\033[0;36m█\033[0;37m     \033[0;36m█\033[0;96;46m█\033[0;36m██\033[0;96;46m▓\033[0;37m   \033[0;36m▐\033[0;96;46m▀\033[0;97;46m█\033[0;96;46m█\033[0;36m█\033[0;37m     \033[0;36m█\033[0;96;46m█\033[0;36m██\033[0;96;46m▓\033[0;37m    \033[0;36m█\033[0;97;46m██\033[0;96;46m█\033[0;36m█\033[0;37m     \033[0;36m█\033[0;37m  \033[0;96;46m░\033[0;36m█\033[0;37m   \033[0;96;46m▓\033[0;36m██\033[0;96;46m█\033[0;36m█\033[0;37m     \033[0;36m▐\033[0;96;46m█\033[0;97;46m█\033[0;96;46m▀\033[0;36m█▌\033[0;37m  \033[0;36m▐\033[0;96;46m▀▀▓░\033[0;37m     \033[0;36m█\033[0;96;46m█\033[0;97;46m█\033[0;96;46m▌\033[0;36m▌\033[0;37m   \033[0;36m▐\033[0;96;46m▀▀▓░\033[0;37m     \033[0;36m█\033[0;96;46m█\033[0;97;46m█\033[0;96;46m▌\033[0;36m▌\033[0;37m   \033[0;96;46m▓\033[0;36m██\033[0;96;46m█\033[0;36m█\033[0;37m     \033[0;96;46m █\033[0;97;46m█\033[0;96;46m░\033[0;36m▌\033[0;37m  \033[0;36m▐\033[0;96;46m▀▀▓░\033[0;37m     \033[0;36m█\033[0;96;46m█\033[0;97;46m█\033[0;96;46m▌\033[0;36m▌\033[0;37m \033[0m
\033[0;37m   \033[0;36m▀\033[0;96;46m▀░\033[0;36m▄\033[0;37m    \033[0;96;46m░░\033[0;37m  \033[0;96;46m▒\033[0;37m     \033[0;36m▀\033[0;96;46m▀░\033[0;36m▄\033[0;37m    \033[0;96;46m░░\033[0;37m  \033[0;96;46m▒\033[0;37m    \033[0;96;46m░██▓░\033[0;37m    \033[0;36m▄\033[0;96;46m▀\033[0;36m█▀▀\033[0;37m    \033[0;96;46m▒\033[0;37m  \033[0;96;46m░░\033[0;37m     \033[0;96;46m░▀\033[0;36m▄▄█▌\033[0;37m  \033[0;96;46m▒\033[0;37m   \033[0;36m█\033[0;37m    \033[0;36m▄\033[0;96;46m░▒\033[0;36m▀▀\033[0;37m    \033[0;96;46m▒\033[0;37m   \033[0;36m█\033[0;37m    \033[0;36m▄\033[0;96;46m░▒\033[0;36m▀▀\033[0;37m    \033[0;96;46m▒\033[0;37m  \033[0;96;46m░░\033[0;37m    \033[0;36m▄\033[0;96;46m▒▀\033[0;36m▀▀\033[0;37m   \033[0;96;46m▒\033[0;37m   \033[0;36m█\033[0;37m    \033[0;36m▄\033[0;96;46m░▒\033[0;36m▀▀\033[0;37m  \033[0m
\033[0;37m     \033[0;36m  ▀▀▄▄\033[0;96;46m▀▒\033[0;36m█\033[0;96;46m▄▓\033[0;37m        \033[0;36m▀▀▄▄▄\033[0;96;46m▀▒\033[0;36m█\033[0;96;46m▄▓\033[0;37m    \033[0;36m█\033[0;96;46m▒▀░░\033[0;36m▀▀▀▀\033[0;37m         \033[0;96;46m▓▄\033[0;36m█\033[0;96;46m▒▀\033[0;37m     \033[0;36m▐▄▄▄█▌\033[0;37m  \033[0;96;46m▀▄\033[0;36m█\033[0;96;46m░▀\033[0;36m▀▀▀▀\033[0;37m         \033[0;96;46m▀▄\033[0;36m█\033[0;96;46m░▀\033[0;36m▀▀▀▀\033[0;37m         \033[0;96;46m▓▄\033[0;36m█\033[0;96;46m▒▀\033[0;36m▀▀▀▀\033[0;37m        \033[0;96;46m▀▄\033[0;36m█\033[0;96;46m░▀\033[0;36m▀▀▀▀\033[0;37m       \033[0m
\033[0;37m \033[0;36m▄\033[0;96;46m▄▄░▀\033[0;36m▀\033[0;37m       \033[0;36m▀▀▄\033[0;37m               \033[0;36m▀▀▄\033[0;37m  \033[0;36m▄▀▀\033[0;37m               \033[0;36m▄▀▀\033[0;37m               \033[0;36m▄\033[0;96;46m░\033[0;36m▀\033[0;37m               \033[0;36m▄\033[0;96;46m░\033[0;36m▀\033[0;37m               \033[0;36m▄▀▀\033[0;37m              \033[0;36m▄\033[0;96;46m░\033[0;36m▀\033[0;37m              \033[0m
\033[0;36m▐\033[0;96;46m▒\033[0;96;43m▓\033[0;97m█\033[0;96;46m░\033[0;36m▌\033[0;37m          \033[0;36m▐▌\033[0;37m                \033[0;36m▐▌▐▌\033[0;37m                \033[0;36m▐▌\033[0;37m                \033[0;36m▐▌\033[0;37m                \033[0;36m▐▌\033[0;37m                \033[0;36m▐▌\033[0;37m               \033[0;36m▐▌\033[0;37m                \033[0m
\033[0;37m \033[0;36m▀▀\033[0;96;46m░▀▄\033[0;36m▄\033[0;37m       \033[0;36m▄■▀\033[0;37m               \033[0;36m▄\033[0;37m \033[0;36m▀\033[0;37m  \033[0;36m▀\033[0;37m \033[0;36m▄\033[0;37m               \033[0;36m▀\033[0;37m \033[0;36m▄\033[0;37m               \033[0;36m▀\033[0;37m \033[0;36m▄\033[0;37m               \033[0;36m▀\033[0;37m \033[0;36m▄\033[0;37m               \033[0;36m▀\033[0;37m \033[0;36m▄\033[0;37m              \033[0;36m▀\033[0;37m \033[0;36m▄\033[0;37m              \033[0m
\033[0m"""
    if sys.stdout.isatty() and not os.environ.get('NO_COLOR'):
        print(_banner)
    else:
        # Not a TTY (or NO_COLOR set): strip ANSI so the art stays readable
        import re
        print(re.sub(r'\x1b\[[0-9;]*m', '', _banner))
elif '--quiet' not in sys.argv and '-q' not in sys.argv:
    if not _quiet_mode:
        print()

def parse_args():
    parser = DescFirstArgumentParser(
        prog="hashgauntlet",
        description=textwrap.dedent(f"""{CYAN}HashGauntlet - AD Credential Auditing\nv3.0.0\nKnight Light AI Security{RESET}"""),
        formatter_class=HelpFormatter,
        add_help=False,
        usage="%(prog)s [OPTIONS]... [--secretsdump FILE | --hash-file FILE --hash-mode MODE] BASE_WORDLIST",
    )

    # Required Inputs
    required = parser.add_argument_group("Required Inputs")
    required.add_argument('--secretsdump', '--sd',
                          help='Path to secretsdump output file (auto-extracts NTLM hashes and maps to usernames)')
    required.add_argument('--ad-mode', action='store_true',
                          help='AD audit mode: auto-sets --hash-mode 1000 and NTLM-safe defaults')
    required.add_argument('-f', '--hash-file',
                          help='Path to hash file (use --secretsdump to auto-generate from secretsdump output)')
    required.add_argument('-m', '--hash-mode', type=int,
                          help='Hashcat hash mode (set automatically when using --ad-mode)')
    required.add_argument('-b', '--base-wordlist',
                          help='Base wordlist to use')

    # Behavior & Limits
    limits = parser.add_argument_group("Behavior & Limits")
    limits.add_argument('--max-time', type=float, default=3.0,
                        help='Max time per attempt in hours')
    limits.add_argument('--max-size', type=int, default=100000,
                        help='Max wordlist size in MB')
    limits.add_argument('-w', '--workload', type=int, default=4, choices=[1, 2, 3, 4],
                        help='Hashcat workload profile')
    limits.add_argument('-c', '--coverage', type=int, default=1, choices=[1, 2, 3],
                        help='Audit thoroughness: 1=optimized (~90%%), 2=extended (~95%%), 3=comprehensive (~98%%)')

    # Paths & Files
    paths = parser.add_argument_group("Paths & Files")
    paths.add_argument('--log-file', default='hashgauntlet.log',
                       help='Output log file (stores cracked hashes with timestamps for severity classification)')
    paths.add_argument('--report',
                       help='Output path for categorized findings report (Critical/High/Medium tiers)')
    paths.add_argument('--report-format', choices=['txt', 'json', 'csv', 'all'], default='txt',
                       help='Findings report format(s): txt (default), json, csv, or all (writes sibling .txt/.json/.csv)')
    paths.add_argument('--encrypt-log', action='store_true',
                       help='Encrypt the audit log with AES-256-GCM (prompts for passphrase at session end)')
    paths.add_argument('-r', '--rules-dir', default='rules',
                       help='Hashcat rules directory')
    paths.add_argument('--hashcat-bin', default='hashcat',
                       help='Path to hashcat binary')
    paths.add_argument('--temp-dir', default=None,
                       help='Directory for temporary wordlists')

    # Selection & Toggles
    toggles = parser.add_argument_group("Selection & Toggles")
    toggles.add_argument('--void-rules', nargs='+', default=[],
                         help='Rule files to skip')
    toggles.add_argument('-d', '--disable-rules', action='store_true',
                         help='Disable all rule-based attacks')
    toggles.add_argument('--skip-combos', action='store_true',
                         help='Skip two-rule combination attacks')
    toggles.add_argument('--no-leet', action='store_true',
                         help='Skip leetspeak preprocessing, generation, and attacks')
    toggles.add_argument('-t', '--toggles', type=str, default='0',
                         help='Toggle depths: "1", "2", "3", or comma-separated "1,2,3" (default: "2")')
    toggles.add_argument('--keep-wordlists', action='store_true',
                         help="Keep intermediate wordlists")
    toggles.add_argument('--debug', action='store_true',
                         help='Enable debug output')

    # Preprocessing Options
    preprocess = parser.add_argument_group("Optimizations")
    preprocess.add_argument('--preprocess', action='store_true',
                            help='Enable wordlist preprocessing')
    preprocess.add_argument('--case', nargs='+', choices=['lower', 'upper', 'pascal', 'sentence', 'title', 'all'],
                            default=[], help='Case conversions to apply')
    preprocess.add_argument('--separators', nargs='+', default=[],
                            help='Separator transformations')
    preprocess.add_argument('--selective-leet', type=int, metavar='N',
                            help='Apply selective leetspeak with max substitutions')
    preprocess.add_argument('--cache-dir', default='.hashgauntlet_cache',
                            help='Directory for cached preprocessed wordlists')
    preprocess.add_argument('--use-cache', action='store_true',
                            help='Use cached wordlists if available')
    preprocess.add_argument('--org-name',
                            help='Organization name for tailored wordlist generation')
    preprocess.add_argument('--org-location', nargs='+',
                            help='Geographic identifier(s) for tailored wordlist generation')

    # Hashcat Kernel Options
    kernels = parser.add_argument_group("Hashcat Kernel Options")
    kernels.add_argument('-O', '--optimize-kernels', action='store_true',
                         help='Use Hashcat optimized kernels')
    kernels.add_argument('--force', action='store_true',
                         help='Force -O on all attacks')
    kernels.add_argument('-S', '--slow-candidates', action='store_true',
                         help='Enable slow candidates')

    # General
    general = parser.add_argument_group("General")
    general.add_argument('-q', '--quiet', action='store_true',
                         help='Suppress all output except errors and cracked hashes')
    general.add_argument('-h', '--help', action='help',
                         help='Show this help message and exit')

    return parser.parse_args()


def log_message(message, log_file=None, end='\n', flush=False):
    """Print and optionally log a message"""
    global _quiet_mode

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Handle carriage return for progress updates
    if message.startswith('\r'):
        full_message = f"\r[{timestamp}] {message[1:]}"
    else:
        full_message = f"[{timestamp}] {message}"

    # Only print if not in quiet mode
    if not _quiet_mode:
        print(full_message, end=end, flush=flush)

    if log_file:
        with open(log_file, 'a', encoding='utf-8') as f:
            # Don't write carriage return to log file
            clean_message = full_message.lstrip('\r')
            f.write(clean_message + '\n')

def format_crack_count(new_cracks, total_cracks, newly_cracked=None, total_hashes=None):
    """
    Format crack count

    Args:
        new_cracks: Number of new cracks in this attack
        total_cracks: Total number of cracks so far
        newly_cracked: Dict of {hash: password} for newly cracked hashes (optional, not used)
        total_hashes: Total number of hashes in hash file (optional)

    Returns:
        Formatted string with crack counts
    """
    # Format: New cracks | Total cracks
    if total_hashes is not None:
        result = f"New cracks: {new_cracks} | Total cracks: {total_cracks}/{total_hashes}"
    else:
        result = f"New cracks: {new_cracks} | Total cracks: {total_cracks}"

    return result


def format_size(size_mb):
    """Format file size in human-readable format"""
    if size_mb < 0.1:  # Less than 100KB
        return f"{size_mb * 1024:.1f}KB"
    else:
        return f"{size_mb:.1f}MB"


def calculate_mask_length(prepend_mask='', append_mask=''):
    """
    Calculate total character length added by mask patterns

    Args:
        prepend_mask: Mask to prepend (e.g., '?d?d')
        append_mask: Mask to append (e.g., '?s')

    Returns:
        int: Total characters that will be added
    """
    total_length = 0

    for mask in [prepend_mask, append_mask]:
        if not mask:
            continue
        i = 0
        while i < len(mask):
            if mask[i:i+2] in ['?d', '?s', '?l', '?u', '?a']:
                total_length += 1
                i += 2
            else:
                i += 1

    return total_length


def get_wordlist_max_length(wordlist_path, sample_size=10000):
    """
    Get maximum word length from a wordlist (samples first N words for performance)

    Args:
        wordlist_path: Path to wordlist file
        sample_size: Number of words to sample (0 = all words)

    Returns:
        int: Maximum word length found
    """
    try:
        max_len = 0
        count = 0

        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if word:
                    max_len = max(max_len, len(word))
                    count += 1
                    if sample_size > 0 and count >= sample_size:
                        break

        return max_len
    except Exception:
        # If we can't read the file, return conservative estimate
        return 50


def presplit_wordlists_by_length(wordlist_path, hash_mode, output_dir, current_count=0, total_count=6):
    """
    Pre-split wordlist into multiple files by character length for all possible mask sizes.

    Creates 6 iterations (for mask sizes 0-5 chars) with 2 files each:
    - within_{max_length}.txt - words within optimized kernel limit
    - over_{max_length}.txt - words over optimized kernel limit

    Args:
        wordlist_path: Path to original wordlist
        hash_mode: Hashcat hash mode to determine optimized limit
        output_dir: Directory to save split wordlists
        current_count: Starting count for progress display (for multi-wordlist splitting)
        total_count: Total count for progress display (6 or 12 depending on --no-leet)

    Returns:
        dict: {max_length: {'within': path, 'over': path}} or None on failure
    """
    global _presplit_wordlist_cache, _temp_files

    try:
        # Get optimized limit for this hash mode
        opt_limit = OPTIMIZED_LIMITS.get(hash_mode, 31)

        # Quick check: if ALL words fit even with largest mask (5 chars), no splitting needed
        max_word_len = get_wordlist_max_length(wordlist_path, sample_size=0)
        if max_word_len <= (opt_limit - 5):
            # All words fit within optimized kernel limit even with 5-char masks
            # No splitting needed - return None to indicate no cache created
            if not _quiet_mode:
                log_message(f"  All words ≤{opt_limit - 5} chars - no splitting needed", None)
            return None

        # Calculate the 6 max_length thresholds we need
        # (for masks of 0, 1, 2, 3, 4, 5 characters)
        max_lengths = [
            opt_limit,      # No mask (straight dictionary)
            opt_limit - 1,  # 1-char mask
            opt_limit - 2,  # 2-char mask
            opt_limit - 3,  # 3-char mask
            opt_limit - 4,  # 4-char mask
            opt_limit - 5,  # 5-char mask
        ]

        base_name = os.path.basename(wordlist_path)

        # Process each length threshold SEQUENTIALLY (not simultaneously)
        # This avoids Windows file handle exhaustion
        file_handles = {}

        # Read wordlist into memory once
        words = []
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip()]

        # Process each length threshold separately (only 2 files open at a time)
        for ml in max_lengths:
            wpath = os.path.join(output_dir, f"presplit_within_{ml}_{base_name}")
            opath = os.path.join(output_dir, f"presplit_over_{ml}_{base_name}")

            within_count = 0
            over_count = 0

            # Open, write, and close files for this threshold
            with open(wpath, 'w', encoding='utf-8', buffering=8192) as wf:
                with open(opath, 'w', encoding='utf-8', buffering=8192) as of:
                    for word in words:
                        if len(word) <= ml:
                            wf.write(word + '\n')
                            within_count += 1
                        else:
                            of.write(word + '\n')
                            over_count += 1

            # Store results
            file_handles[ml] = {
                'within': {'path': wpath, 'count': within_count},
                'over': {'path': opath, 'count': over_count}
            }

            current_count += 2
            log_message(f"\rPrepared candidate segments [{current_count}/{total_count}]...", end='', flush=True)

        # Small delay to ensure Windows releases all handles
        time.sleep(0.05)

        # Build result dict and register non-empty files for cleanup
        result = {}
        for max_len in max_lengths:
            within_info = file_handles[max_len]['within']
            over_info = file_handles[max_len]['over']

            result[max_len] = {
                'within': within_info['path'] if within_info['count'] > 0 else None,
                'over': over_info['path'] if over_info['count'] > 0 else None
            }

            # Register for cleanup
            if within_info['count'] > 0:
                _temp_files.append(within_info['path'])
            else:
                # Remove empty file
                try:
                    os.remove(within_info['path'])
                except:
                    pass

            if over_info['count'] > 0:
                _temp_files.append(over_info['path'])
            else:
                # Remove empty file
                try:
                    os.remove(over_info['path'])
                except:
                    pass

        # Cache the result
        _presplit_wordlist_cache[wordlist_path] = result

        return result

    except Exception as e:
        # Files are auto-closed by context managers, just log the error
        if not _quiet_mode:
            import traceback
            print(f"Warning: Failed to pre-split wordlist: {e}")
            print(f"  File: {wordlist_path}")
            traceback.print_exc()

        return None


def split_wordlist_by_length(wordlist_path, max_length, output_dir):
    """
    Split wordlist into two files: words within limit and words over limit.

    First checks cache for pre-split wordlists. Falls back to on-the-fly splitting if not cached.

    Args:
        wordlist_path: Path to original wordlist
        max_length: Maximum word length for optimized kernel
        output_dir: Directory to save split wordlists

    Returns:
        tuple: (within_limit_path, over_limit_path)
               Returns (None, None) if all words are within limit
               Returns (wordlist_path, None) if all words are within limit
    """
    global _presplit_wordlist_cache

    try:
        # Check if we have a pre-split version in cache
        if wordlist_path in _presplit_wordlist_cache:
            cache = _presplit_wordlist_cache[wordlist_path]
            if max_length in cache:
                within_path = cache[max_length]['within']
                over_path = cache[max_length]['over']

                # Return cached paths
                # If both are None, all words fit - use original wordlist
                if within_path is None and over_path is None:
                    return (wordlist_path, None)

                return (within_path, over_path)

        # Fallback: No cache hit, do on-the-fly splitting (check ALL words for accuracy)
        max_word_len = get_wordlist_max_length(wordlist_path, sample_size=0)  # Check ALL words
        if max_word_len <= max_length:
            # All words within limit - no splitting needed
            return (wordlist_path, None)

        # Need to split - create filtered wordlists
        base_name = os.path.basename(wordlist_path)
        within_path = os.path.join(output_dir, f"opt_{max_length}_down_{base_name}")
        over_path = os.path.join(output_dir, f"opt_{max_length}_up_{base_name}")

        within_count = 0
        over_count = 0

        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f_in:
            with open(within_path, 'w', encoding='utf-8') as f_within:
                with open(over_path, 'w', encoding='utf-8') as f_over:
                    for line in f_in:
                        word = line.strip()
                        if not word:
                            continue

                        if len(word) <= max_length:
                            f_within.write(word + '\n')
                            within_count += 1
                        else:
                            f_over.write(word + '\n')
                            over_count += 1

        # Register for cleanup
        global _temp_files
        if within_count > 0:
            _temp_files.append(within_path)
        if over_count > 0:
            _temp_files.append(over_path)

        # Return paths (or None if a file would be empty)
        return (
            within_path if within_count > 0 else None,
            over_path if over_count > 0 else None
        )

    except Exception:
        # If splitting fails, use original wordlist without -O
        return (wordlist_path, None)


def should_use_optimized_kernel(hash_mode, wordlist_path, prepend_mask='', append_mask=''):
    """
    Check if -O flag is safe for this specific attack

    Args:
        hash_mode: Hashcat hash mode
        wordlist_path: Path to wordlist
        prepend_mask: Mask to prepend
        append_mask: Mask to append

    Returns:
        bool: True if -O is safe (won't skip passwords), False otherwise
    """
    # Get limit for this hash mode (default to 31 if unknown)
    opt_limit = OPTIMIZED_LIMITS.get(hash_mode, 31)

    # Calculate total password length
    mask_length = calculate_mask_length(prepend_mask, append_mask)
    max_word_length = get_wordlist_max_length(wordlist_path, sample_size=0)  # Check all words now
    max_password_length = max_word_length + mask_length

    # Safe if all passwords will be within limit
    return max_password_length <= opt_limit


def log_separator(log_file=None):
    """Print a separator line (accounts for timestamp length)"""
    separator = "=" * 58  # 58 + timestamp (22 chars) = 80 total
    log_message(separator, log_file)


def log_cracked(hash_val, plaintext, log_file):
    """Log a cracked hash and always print it (even in quiet mode)"""
    global _quiet_mode

    # Always print cracked hashes, even in quiet mode
    print(f"{CYAN}{hash_val}:{plaintext}{RESET}")

    # Write to log file
    with open(log_file, 'a') as f:
        f.write(f"CRACKED: {hash_val}:{plaintext}\n")


def log_skipped(method, reason, est_size, log_file):
    """Log a skipped attempt"""
    with open(log_file, 'a') as f:
        f.write(f"SKIPPED: {method} [REASON: {reason}, SIZE: {est_size:.1f}MB]\n")


def get_wordlists_sorted(directory):
    """Get all wordlists from directory sorted by size (smallest first)"""
    wordlists = []

    try:
        for file in Path(directory).iterdir():
            if file.is_file() and not file.name.startswith('.'):
                size_mb = file.stat().st_size / (1024 * 1024)
                wordlists.append((str(file), size_mb))
    except FileNotFoundError:
        return []

    # Sort by size (smallest first)
    wordlists.sort(key=lambda x: x[1])
    return wordlists


def get_rule_files(rules_dir):
    """Get all rule files from rules directory"""
    rule_files = []

    if not os.path.exists(rules_dir):
        return rule_files

    for file in Path(rules_dir).iterdir():
        if file.is_file() and file.suffix == '.rule':
            rule_files.append(str(file))

    # Sort by common rule priority
    priority_rules = ['best66.rule', 'toggles1.rule', 'd3adhob0.rule', 'dive.rule', 'toggles2.rule']

    sorted_rules = []
    remaining_rules = rule_files.copy()  # Create a copy to avoid modification during iteration

    for priority in priority_rules:
        for rule in rule_files:
            if priority in rule and rule in remaining_rules:
                sorted_rules.append(rule)
                remaining_rules.remove(rule)
                break

    # Add remaining rules
    sorted_rules.extend(remaining_rules)

    return sorted_rules


def count_wordlist_lines(wordlist_path):
    """Count lines in a wordlist file"""
    try:
        with open(wordlist_path, 'rb') as f:
            return sum(1 for _ in f)
    except:
        return 0


def count_hash_lines(hash_file):
    """Count lines in hash file"""
    try:
        with open(hash_file, 'rb') as f:
            return sum(1 for _ in f)
    except:
        return 1


def run_hashcat_attack_single(hashcat_bin, hash_file, hash_mode, wordlist_path, output_dir,
                              rules=None, timeout_hours=None, workload=4, use_optimized=False, slow_candidates=False,
                              attack_mode=0, mask=None):
    """
    Run a single hashcat attack (internal function - use run_hashcat_attack instead)

    Args:
        use_optimized: Whether to use -O flag for this specific run
        attack_mode: Hashcat attack mode (0=dictionary, 6=hybrid wordlist+mask, 7=hybrid mask+wordlist)
        mask: Mask pattern for hybrid attacks (e.g., '?d?d?d?d')
    """
    global _session_control, _rich_live

    potfile = os.path.join(output_dir, 'hashgauntlet.potfile')

    # Build command
    cmd = [
        hashcat_bin,
        '-m', str(hash_mode),
        '-a', str(attack_mode),
        hash_file,
        wordlist_path,
        '--potfile-path', potfile,
        '-w', str(workload),
        '--status',           # Force status updates even when stdout is redirected
        '--status-timer=1'    # Update status every 1 second
    ]

    # Add mask for hybrid attacks
    if attack_mode == 6 and mask:
        # Attack mode 6: wordlist + mask (append)
        cmd.append(mask)
    elif attack_mode == 7 and mask:
        # Attack mode 7: mask + wordlist (prepend)
        # For -a 7, mask comes before wordlist in command
        cmd.remove(wordlist_path)
        cmd.insert(cmd.index(hash_file) + 1, mask)
        cmd.insert(cmd.index(mask) + 1, wordlist_path)

    # Add -O flag if requested for this specific run
    if use_optimized:
        cmd.append('-O')

    if slow_candidates:
        cmd.append('-S')

    if rules:
        for rule in rules:
            cmd.extend(['-r', rule])

    # Run attack with Popen for interactive control
    start_time = time.time()
    timeout_seconds = (timeout_hours * 3600) if timeout_hours else None
    status = 'completed'

    try:
        # Start hashcat process with stdin for interactive commands
        # Use unbuffered mode to see output immediately
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,       # Use text mode for automatic encoding
            bufsize=1        # Line buffered
        )

        # Register process with session control
        _session_control.set_process(process)

        # Monitor process while it runs
        while True:
            # Check for timeout
            if timeout_seconds and (time.time() - start_time) > timeout_seconds:
                process.terminate()
                time.sleep(1)
                if process.poll() is None:
                    process.kill()
                status = 'timeout'
                break

            # Check session control flags
            if _session_control.should_kill():
                process.kill()
                status = 'killed'
                break

            if _session_control.should_skip():
                process.terminate()
                time.sleep(0.5)
                if process.poll() is None:
                    process.kill()
                status = 'skipped'
                break

            # Handle pause state
            while _session_control.is_paused():
                time.sleep(0.5)
                # Check if kill was pressed during pause
                if _session_control.should_kill():
                    process.kill()
                    status = 'killed'
                    break

            # Check if process has finished
            if process.poll() is not None:
                break

            # Read output line by line
            try:
                line = process.stdout.readline()

                if line:
                    # Mark that status is now available (first time we see "Session" line)
                    if line.startswith('Session') and not _session_control.is_status_available():
                        _session_control.mark_status_available()
                        # Update the Rich status bar to show [s]tatus option
                        if _rich_live:
                            _rich_live.update(Group("", create_status_bar_text()))

                    # If status requested and we see "Session" line, print status block
                    if _session_control.should_show_status() and line.startswith('Session'):
                        print("\n")
                        print(line.strip())
                        sys.stdout.flush()

                        # Read rest of status block until blank line
                        for _ in range(30):
                            next_line = process.stdout.readline()
                            if not next_line or next_line.strip() == '':
                                break
                            print(next_line.strip())
                            sys.stdout.flush()

                        print("\n")
                        sys.stdout.flush()
                        _session_control.clear_status_request()
                else:
                    time.sleep(0.1)
            except:
                pass

            time.sleep(0.05)

        # Drain remaining output
        try:
            remaining = process.stdout.read()
        except:
            pass

        # Clean up process
        try:
            process.stdout.close()
            process.stdin.close()
        except:
            pass

    except Exception as e:
        status = 'error'
        print(f"{CYAN}[!] Error running hashcat: {e}{RESET}")

    elapsed_hours = (time.time() - start_time) / 3600

    # Clear process from session control
    _session_control.set_process(None)

    # Give GPU time to release VRAM before next attack
    # Prevents memory fragmentation and performance degradation
    time.sleep(2)

    # Parse potfile for new cracks
    cracked = parse_potfile(potfile)

    return {
        'cracked': cracked,
        'elapsed_hours': elapsed_hours,
        'status': status
    }


def run_hashcat_attack(hashcat_bin, hash_file, hash_mode, wordlist_path, output_dir,
                       rules=None, timeout_hours=None, workload=4, optimize_kernels=False, slow_candidates=False,
                       attack_mode=0, mask=None, first_mask_length=0):
    """
    Run hashcat attack with two-pass optimization strategy.

    Pass 1: Words within optimized kernel limit WITH -O (fast)
    Pass 2: Over-length words WITHOUT -O (slow but complete)

    Args:
        attack_mode: Hashcat attack mode (0=dictionary, 6=hybrid wordlist+mask, 7=hybrid mask+wordlist)
        mask: Mask pattern for hybrid attacks (e.g., '?d?d?d?d')
        optimize_kernels: Whether user requested -O flag
        first_mask_length: Length of first mask for two-sided attacks (already in intermediate wordlist)
    """
    global _session_control, _rich_live

    # Reset status availability for new attack and update status bar
    _session_control.reset_status_availability()
    if _rich_live:
        _rich_live.update(Group("", create_status_bar_text()))

    # If user didn't request -O, just run single pass without optimization
    if not optimize_kernels:
        return run_hashcat_attack_single(
            hashcat_bin, hash_file, hash_mode, wordlist_path, output_dir,
            rules=rules, timeout_hours=timeout_hours, workload=workload,
            use_optimized=False, slow_candidates=slow_candidates,
            attack_mode=attack_mode, mask=mask
        )

    # Calculate maximum word length for optimized kernel
    opt_limit = OPTIMIZED_LIMITS.get(hash_mode, 31)
    mask_length = calculate_mask_length(
        mask if attack_mode == 7 else '',  # prepend mask
        mask if attack_mode == 6 else ''   # append mask
    )

    # Add first mask length for two-sided attacks (intermediate wordlists)
    total_mask_length = mask_length + first_mask_length
    max_word_length = opt_limit - total_mask_length

    # Split wordlist by length
    within_limit_path, over_limit_path = split_wordlist_by_length(
        wordlist_path, max_word_length, output_dir
    )

    # Pass 1: Run words within limit WITH -O (fast pass)
    if within_limit_path:
        if not _quiet_mode:
            log_message(f"  └─ Pass 1/2: Optimized kernel (≤{max_word_length} chars)")

        result1 = run_hashcat_attack_single(
            hashcat_bin, hash_file, hash_mode, within_limit_path, output_dir,
            rules=rules, timeout_hours=timeout_hours, workload=workload,
            use_optimized=True, slow_candidates=slow_candidates,
            attack_mode=attack_mode, mask=mask
        )
    else:
        # No words within limit - return empty result
        result1 = {'cracked': {}, 'elapsed_hours': 0, 'status': 'skipped'}

    # Pass 2: Run over-length words WITHOUT -O (slow but complete)
    if over_limit_path:
        if not _quiet_mode:
            log_message(f"  └─ Pass 2/2: Pure kernel (>{max_word_length} chars)")

        result2 = run_hashcat_attack_single(
            hashcat_bin, hash_file, hash_mode, over_limit_path, output_dir,
            rules=rules, timeout_hours=timeout_hours, workload=workload,
            use_optimized=False, slow_candidates=slow_candidates,
            attack_mode=attack_mode, mask=mask
        )

        # Merge results
        result1['cracked'].update(result2['cracked'])
        result1['elapsed_hours'] += result2['elapsed_hours']
        if result2['status'] != 'completed':
            result1['status'] = result2['status']

    return result1


def parse_potfile(potfile_path):
    """Parse hashcat potfile and return dict of {hash: plaintext}"""
    cracked = {}
    
    if not os.path.exists(potfile_path):
        return cracked
    
    try:
        with open(potfile_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        cracked[parts[0]] = parts[1]
    except:
        pass
    
    return cracked


def safe_delete_file(filepath, max_retries=3, log_file=None):
    """
    Safely delete a file with retry logic for Windows file lock issues.

    Args:
        filepath: Path to file to delete
        max_retries: Maximum number of retry attempts
        log_file: Optional log file for error messages

    Returns:
        True if deleted successfully, False otherwise
    """
    global _temp_files

    if not filepath or not os.path.exists(filepath):
        # Remove from tracking even if file doesn't exist
        if filepath in _temp_files:
            _temp_files.remove(filepath)
        return True

    for attempt in range(max_retries):
        try:
            os.remove(filepath)
            # Remove from tracking on successful deletion
            if filepath in _temp_files:
                _temp_files.remove(filepath)
            return True
        except PermissionError:
            # Windows file lock - wait and retry
            if attempt < max_retries - 1:
                time.sleep(0.5 * (attempt + 1))  # Exponential backoff: 0.5s, 1s, 1.5s
                continue
            else:
                # Final attempt failed
                if log_file:
                    log_message(f"Warning: Could not delete {os.path.basename(filepath)} (file in use)", log_file)
                return False
        except Exception as e:
            # Other error - log and return
            if log_file:
                log_message(f"Warning: Could not delete {os.path.basename(filepath)}: {e}", log_file)
            return False

    return False


def calculate_mask_combinations(mask_pattern):
    """Calculate number of combinations for a mask pattern"""
    total = 1
    i = 0
    while i < len(mask_pattern):
        if i < len(mask_pattern) - 1 and mask_pattern[i] == '?':
            mask_char = mask_pattern[i:i+2]
            if mask_char in MASK_SIZES:
                total *= MASK_SIZES[mask_char]
                i += 2
                continue
        i += 1
    return total


def determine_optimal_two_sided_strategy(prepend_mask, append_mask):
    """
    Determine optimal strategy for two-sided mask attacks.

    Returns tuple: (smaller_mask, larger_mask, use_prepend_first)
    - smaller_mask: Apply this to wordlist first (generates temp file)
    - larger_mask: Use this in hybrid mode with hashcat
    - use_prepend_first: True if smaller mask should be prepended, False if appended
    """
    prepend_combos = calculate_mask_combinations(prepend_mask)
    append_combos = calculate_mask_combinations(append_mask)

    if prepend_combos <= append_combos:
        # Prepend is smaller or equal - apply prepend first, then use hybrid append
        return (prepend_mask, append_mask, True)
    else:
        # Append is smaller - apply append first, then use hybrid prepend
        return (append_mask, prepend_mask, False)


def estimate_masked_wordlist_size(base_wordlist, prepend_mask='', append_mask=''):
    """Estimate size of masked wordlist in MB"""
    try:
        # Sample base wordlist to get average word length
        sample_words = []
        with open(base_wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= 1000:
                    break
                sample_words.append(line.strip())
        
        if not sample_words:
            return 999999  # Unknown, assume huge
        
        avg_word_len = sum(len(w) for w in sample_words) / len(sample_words)
        total_words = count_wordlist_lines(base_wordlist)
        
        # Calculate mask combinations
        prepend_combos = calculate_mask_combinations(prepend_mask) if prepend_mask else 1
        append_combos = calculate_mask_combinations(append_mask) if append_mask else 1
        total_combos = prepend_combos * append_combos
        
        # Calculate mask lengths
        prepend_len = len(prepend_mask.replace('?', '')) // 2 if prepend_mask else 0
        append_len = len(append_mask.replace('?', '')) // 2 if append_mask else 0
        
        # Calculate total size
        avg_line_len = prepend_len + avg_word_len + append_len + 1  # +1 for newline
        total_lines = total_words * total_combos
        total_bytes = total_lines * avg_line_len
        size_mb = total_bytes / (1024 * 1024)
        
        return size_mb
        
    except:
        return 999999  # Unknown, assume huge


def generate_masked_wordlist(base_wordlist, prepend_mask='', append_mask='', temp_dir=None, debug=False, hashcat_bin='hashcat'):
    """
    Generate a masked wordlist using hashcat or Python.

    NOTE: This function is now ONLY used for two-sided masks (prepend AND append).
    Single-sided masks use hybrid attack modes (-a 6/-a 7) directly for 10-100x speedup.
    """
    global _temp_files
    output_path = None
    try:
        # Create temp file for output
        if temp_dir:
            os.makedirs(temp_dir, exist_ok=True)
            fd, output_path = tempfile.mkstemp(suffix='.txt', dir=temp_dir)
        else:
            fd, output_path = tempfile.mkstemp(suffix='.txt')
        os.close(fd)

        # Track temp file for cleanup on interrupt
        _temp_files.append(output_path)

        # If only append mask, use hashcat hybrid mode 6
        if append_mask and not prepend_mask:
            cmd = [
                hashcat_bin,
                '--stdout',
                '-a', '6',  # Hybrid wordlist + mask
                base_wordlist,
                append_mask
            ]
            if debug:
                print(f"DEBUG: Running mask generation: {' '.join(cmd)}")

            with open(output_path, 'w', encoding='utf-8', errors='ignore') as outfile:
                result = subprocess.run(cmd, stdout=outfile, stderr=subprocess.PIPE,
                                       text=True, timeout=600)

            if result.returncode == 0:
                return output_path
            else:
                print(f"{CYAN}[!] ERROR:{RESET} Hashcat mask generation failed!")
                print(f"    Command: {' '.join(cmd)}")
                if result.stderr:
                    print(f"    Error output: {result.stderr.strip()}")
                    # Check for common errors
                    if "Token length exception" in result.stderr:
                        print(f"    → Invalid mask pattern: {append_mask}")
                    elif "out of memory" in result.stderr.lower():
                        print(f"    → Out of memory during mask generation")
                    elif "No devices found" in result.stderr or "no such file" in result.stderr.lower():
                        print(f"    → Hashcat device/file issue")
                if output_path and os.path.exists(output_path):
                    safe_delete_file(output_path)
                return None

        # If only prepend mask, use hashcat hybrid mode 7
        elif prepend_mask and not append_mask:
            cmd = [
                hashcat_bin,
                '--stdout',
                '-a', '7',  # Hybrid mask + wordlist
                prepend_mask,
                base_wordlist
            ]
            if debug:
                print(f"DEBUG: Running mask generation: {' '.join(cmd)}")

            with open(output_path, 'w', encoding='utf-8', errors='ignore') as outfile:
                result = subprocess.run(cmd, stdout=outfile, stderr=subprocess.PIPE,
                                       text=True, timeout=600)

            if result.returncode == 0:
                return output_path
            else:
                print(f"{CYAN}[!] ERROR:{RESET} Hashcat mask generation failed!")
                print(f"    Command: {' '.join(cmd)}")
                if result.stderr:
                    print(f"    Error output: {result.stderr.strip()}")
                    # Check for common errors
                    if "Token length exception" in result.stderr:
                        print(f"    → Invalid mask pattern: {prepend_mask}")
                    elif "out of memory" in result.stderr.lower():
                        print(f"    → Out of memory during mask generation")
                    elif "No devices found" in result.stderr or "no such file" in result.stderr.lower():
                        print(f"    → Hashcat device/file issue")
                if output_path and os.path.exists(output_path):
                    safe_delete_file(output_path)
                return None

        # If both masks, use Python to generate combinations
        elif prepend_mask and append_mask:
            return generate_both_masks_wordlist(base_wordlist, prepend_mask, append_mask, output_path)

        # If neither mask, just copy the base wordlist
        else:
            import shutil
            shutil.copy(base_wordlist, output_path)
            return output_path

        # If we get here, something went wrong - clean up
        if output_path and os.path.exists(output_path):
            safe_delete_file(output_path)
        return None

    except subprocess.TimeoutExpired:
        print(f"{CYAN}[!] ERROR:{RESET} Mask generation timed out after 600 seconds")
        print(f"    Mask pattern may be too large: prepend={prepend_mask}, append={append_mask}")
        if output_path and os.path.exists(output_path):
            safe_delete_file(output_path)
        return None
    except Exception as e:
        print(f"{CYAN}[!] ERROR:{RESET} Unexpected error during mask generation: {e}")
        if debug:
            import traceback
            traceback.print_exc()
        if output_path and os.path.exists(output_path):
            safe_delete_file(output_path)
        return None


def generate_both_masks_wordlist(base_wordlist, prepend_mask, append_mask, output_path):
    """Generate wordlist with both prepend and append masks using Python"""
    try:
        # Generate all prepend combinations
        prepend_combos = generate_mask_combinations_list(prepend_mask)
        append_combos = generate_mask_combinations_list(append_mask)
        
        # Read base words
        with open(base_wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            base_words = [line.strip() for line in f if line.strip()]
        
        # Generate all combinations
        with open(output_path, 'w', encoding='utf-8', errors='ignore') as outfile:
            for base_word in base_words:
                for prepend in prepend_combos:
                    for append in append_combos:
                        outfile.write(f"{prepend}{base_word}{append}\n")
        
        return output_path
        
    except Exception as e:
        return None


def generate_intermediate_from_presplit(base_wordlist_path, smaller_mask, larger_mask,
                                         use_prepend_first, hash_mode, temp_dir, debug=False, hashcat_bin='hashcat'):
    """
    Generate intermediate wordlist from pre-split sources using upstream splitting strategy.

    Implements mask budget calculation to select correct pre-split source files, then generates
    safe and unsafe intermediates for two-pass attacks with -O optimization.

    Args:
        base_wordlist_path: Path to original wordlist (e.g., all_marvel_base.txt)
        smaller_mask: Mask with lowest keyspace (applied to create intermediate)
        larger_mask: Mask with higher keyspace (applied during attack)
        use_prepend_first: True if smaller_mask should be prepended, False if appended
        hash_mode: Hashcat hash mode for optimized kernel limit
        temp_dir: Temporary directory for intermediate files
        debug: Enable debug output

    Returns:
        tuple: (safe_intermediate_path, unsafe_intermediate_path) or (None, None) on failure
    """
    global _presplit_wordlist_cache, _temp_files

    try:
        # Calculate total mask length for both masks
        total_mask_length = calculate_mask_length(
            smaller_mask if use_prepend_first else larger_mask,
            larger_mask if use_prepend_first else smaller_mask
        )

        # Get optimized kernel limit
        opt_limit = OPTIMIZED_LIMITS.get(hash_mode, 31)
        max_safe_base_word = opt_limit - total_mask_length

        if debug:
            log_message(f"  Mask budget: total={total_mask_length}, opt_limit={opt_limit}, max_safe_base={max_safe_base_word}")

        # Check if we have pre-split cache for this wordlist
        if base_wordlist_path not in _presplit_wordlist_cache:
            if debug:
                log_message(f"  No pre-split cache found for {os.path.basename(base_wordlist_path)}")
            return (None, None)

        cache = _presplit_wordlist_cache[base_wordlist_path]
        if max_safe_base_word not in cache:
            if debug:
                log_message(f"  No pre-split files for max_length={max_safe_base_word}")
            return (None, None)

        # Get pre-split source files
        within_source = cache[max_safe_base_word]['within']
        over_source = cache[max_safe_base_word]['over']

        if debug:
            log_message(f"  Using pre-split sources for base words ≤{max_safe_base_word}:")
            log_message(f"    Safe: {os.path.basename(within_source) if within_source else 'None'}")
            log_message(f"    Unsafe: {os.path.basename(over_source) if over_source else 'None'}")

        # Generate safe intermediate from within_source
        safe_intermediate = None
        if within_source and os.path.exists(within_source):
            fd, safe_intermediate = tempfile.mkstemp(suffix='_safe.txt', dir=temp_dir)
            os.close(fd)
            _temp_files.append(safe_intermediate)

            # Build hashcat command based on mask position
            if use_prepend_first:
                cmd = [hashcat_bin, '--stdout', '-a', '7', smaller_mask, within_source]
            else:
                cmd = [hashcat_bin, '--stdout', '-a', '6', within_source, smaller_mask]

            with open(safe_intermediate, 'w', encoding='utf-8', errors='ignore') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True, timeout=600)

            if result.returncode != 0:
                if debug:
                    log_message(f"  Failed to generate safe intermediate: {result.stderr}")
                safe_intermediate = None

        # Generate unsafe intermediate from over_source
        unsafe_intermediate = None
        if over_source and os.path.exists(over_source):
            fd, unsafe_intermediate = tempfile.mkstemp(suffix='_unsafe.txt', dir=temp_dir)
            os.close(fd)
            _temp_files.append(unsafe_intermediate)

            # Build hashcat command based on mask position
            if use_prepend_first:
                cmd = [hashcat_bin, '--stdout', '-a', '7', smaller_mask, over_source]
            else:
                cmd = [hashcat_bin, '--stdout', '-a', '6', over_source, smaller_mask]

            with open(unsafe_intermediate, 'w', encoding='utf-8', errors='ignore') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True, timeout=600)

            if result.returncode != 0:
                if debug:
                    log_message(f"  Failed to generate unsafe intermediate: {result.stderr}")
                unsafe_intermediate = None

        return (safe_intermediate, unsafe_intermediate)

    except Exception as e:
        if debug:
            log_message(f"  Error in generate_intermediate_from_presplit: {e}")
            import traceback
            traceback.print_exc()
        return (None, None)


def generate_mask_combinations_list(mask_pattern):
    """Generate list of all combinations for a mask pattern"""
    if not mask_pattern:
        return ['']
    
    # Character sets for each mask
    charsets = {
        '?d': '0123456789',
        '?l': 'abcdefghijklmnopqrstuvwxyz',
        '?u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        '?s': ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~',
        '?a': '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
    }
    
    # Parse mask pattern into list of charsets
    position_charsets = []
    i = 0
    while i < len(mask_pattern):
        if i < len(mask_pattern) - 1 and mask_pattern[i] == '?':
            mask_char = mask_pattern[i:i+2]
            if mask_char in charsets:
                position_charsets.append(charsets[mask_char])
                i += 2
                continue
        # If not a valid mask, treat as literal character
        position_charsets.append(mask_pattern[i])
        i += 1
    
    # Generate all combinations
    if not position_charsets:
        return ['']
    
    combinations = ['']
    for charset in position_charsets:
        new_combinations = []
        for combo in combinations:
            for char in charset:
                new_combinations.append(combo + char)
        combinations = new_combinations
    
    return combinations


def generate_pure_mask_variations():
    """Generate all pure mask variations (prepend, append, both, async)"""
    variations = []
    
    for mask in MASK_PRIORITY:
        # Prepend only (1-4 chars)
        for length in range(1, 5):
            pattern = mask * length
            variations.append({
                'name': f'{pattern} prepend',
                'prepend': pattern,
                'append': ''
            })
        
        # Append only (1-4 chars)
        for length in range(1, 5):
            pattern = mask * length
            variations.append({
                'name': f'{pattern} append',
                'prepend': '',
                'append': pattern
            })
        
        # Both equal (1+1, 2+2, 3+3, 4+4)
        for length in range(1, 5):
            pattern = mask * length
            variations.append({
                'name': f'{pattern} both sides',
                'prepend': pattern,
                'append': pattern
            })
        
        # Async (unequal lengths on each side)
        for pre_len in range(1, 5):
            for app_len in range(1, 5):
                if pre_len != app_len:
                    pre_pattern = mask * pre_len
                    app_pattern = mask * app_len
                    variations.append({
                        'name': f'{pre_pattern} prepend + {app_pattern} append',
                        'prepend': pre_pattern,
                        'append': app_pattern
                    })
    
    return variations


def generate_hybrid_variations():
    """Generate all hybrid mask variations (2-char, 3-char, 4-char)"""
    variations = []
    
    # 2-char hybrids
    for mask1 in MASK_PRIORITY:
        for mask2 in MASK_PRIORITY:
            if mask1 != mask2:
                hybrid = mask1 + mask2
                
                # Append (1 unit = 2 chars, 2 units = 4 chars)
                for units in [1, 2]:
                    pattern = hybrid * units
                    variations.append({
                        'name': f'{pattern} append',
                        'prepend': '',
                        'append': pattern
                    })
                
                # Prepend (1 unit = 2 chars, 2 units = 4 chars)
                for units in [1, 2]:
                    pattern = hybrid * units
                    variations.append({
                        'name': f'{pattern} prepend',
                        'prepend': pattern,
                        'append': ''
                    })
    
    # 3-char hybrids (all permutations of 3 different masks)
    for combo in itertools.permutations(MASK_PRIORITY, 3):
        hybrid = ''.join(combo)
        variations.append({
            'name': f'{hybrid} append',
            'prepend': '',
            'append': hybrid
        })
        variations.append({
            'name': f'{hybrid} prepend',
            'prepend': hybrid,
            'append': ''
        })
    
    # 4-char hybrids (all permutations of 4 different masks)
    for combo in itertools.permutations(MASK_PRIORITY, 4):
        hybrid = ''.join(combo)
        variations.append({
            'name': f'{hybrid} append',
            'prepend': '',
            'append': hybrid
        })
    
    return variations


def generate_cross_mask_variations():
    """Generate cross-mask async variations (different masks on each side)"""
    variations = []
    
    # Same length, different masks
    for mask1 in MASK_PRIORITY:
        for mask2 in MASK_PRIORITY:
            if mask1 != mask2:
                for length in range(1, 5):
                    pre_pattern = mask1 * length
                    app_pattern = mask2 * length
                    variations.append({
                        'name': f'{pre_pattern} prepend + {app_pattern} append',
                        'prepend': pre_pattern,
                        'append': app_pattern
                    })
    
    # Different lengths, different masks
    for mask1 in MASK_PRIORITY:
        for mask2 in MASK_PRIORITY:
            if mask1 != mask2:
                for pre_len in range(1, 5):
                    for app_len in range(1, 5):
                        if pre_len != app_len:
                            pre_pattern = mask1 * pre_len
                            app_pattern = mask2 * app_len
                            variations.append({
                                'name': f'{pre_pattern} prepend + {app_pattern} append',
                                'prepend': pre_pattern,
                                'append': app_pattern
                            })
    
    return variations


def generate_coverage1_attacks():
    """
    Coverage Level 1: NCL-cracking mask variations (36 attacks) ordered by keyspace

    Based on exact patterns from ~/Scripts/ncl-cracking/NCL-cracking/crack.sh
    Ordered by total keyspace (wordlist_size × combinations) for actual speed

    Key insight: Even with pre-created intermediates, two-sided attacks are slower
    because they process larger wordlists (10x-100x base size).

    For same keyspace, ordered by likelihood: Append (3x) > Prepend (1x) > Two-sided (0.5x)

    Expected crack rate: ~90% on common passwords
    Estimated time: 4-6 hours on typical hardware
    """
    variations = []

    # ========================================================================
    # Keyspace: 10W (W = wordlist size)
    # Fastest attacks - append before prepend
    # ========================================================================

    variations.append({'name': '?d append', 'prepend': '', 'append': '?d'})
    variations.append({'name': '?d prepend', 'prepend': '?d', 'append': ''})

    # ========================================================================
    # Keyspace: 33W
    # Single symbol
    # ========================================================================

    variations.append({'name': '?s append', 'prepend': '', 'append': '?s'})
    variations.append({'name': '?s prepend', 'prepend': '?s', 'append': ''})

    # ========================================================================
    # Keyspace: 100W
    # Two digits or ?d+word+?d two-sided (uses d_prepend: 10W × 10 = 100W)
    # ========================================================================

    variations.append({'name': '?d?d append', 'prepend': '', 'append': '?d?d'})
    variations.append({'name': '?d?d prepend', 'prepend': '?d?d', 'append': ''})
    variations.append({'name': '?d + word + ?d', 'prepend': '?d', 'append': '?d', 'two_sided': True})

    # ========================================================================
    # Keyspace: 1,089W
    # Two symbols: ?s+word+?s two-sided (uses s_prepend: 33W × 33 = 1,089W)
    # ========================================================================

    variations.append({'name': '?s + word + ?s', 'prepend': '?s', 'append': '?s', 'two_sided': True})

    # ========================================================================
    # Keyspace: 330W
    # Digit+symbol hybrid or symbol+digit two-sided
    # ========================================================================

    variations.append({'name': 'word + ?d?s', 'prepend': '', 'append': '?d?s'})
    variations.append({'name': 'word + ?s?d', 'prepend': '', 'append': '?s?d'})
    variations.append({'name': '?d?s + word', 'prepend': '?d?s', 'append': ''})
    variations.append({'name': '?s?d + word', 'prepend': '?s?d', 'append': ''})
    variations.append({'name': '?s + word + ?d', 'prepend': '?s', 'append': '?d', 'two_sided': True})
    variations.append({'name': '?d + word + ?s', 'prepend': '?d', 'append': '?s', 'two_sided': True})

    # ========================================================================
    # Keyspace: 1,000W
    # Three digits or small two-sided
    # ========================================================================

    variations.append({'name': '?d?d?d append', 'prepend': '', 'append': '?d?d?d'})
    variations.append({'name': '?d?d?d prepend', 'prepend': '?d?d?d', 'append': ''})
    variations.append({'name': '?d + word + ?d?d', 'prepend': '?d', 'append': '?d?d', 'two_sided': True})
    variations.append({'name': '?d?d + word + ?d', 'prepend': '?d?d', 'append': '?d', 'two_sided': True})

    # ========================================================================
    # Keyspace: 3,300W
    # 2-digit + symbol or symbol + 2-digit two-sided
    # ========================================================================

    variations.append({'name': 'word + ?d?d?s', 'prepend': '', 'append': '?d?d?s'})
    variations.append({'name': 'word + ?s?d?d', 'prepend': '', 'append': '?s?d?d'})
    variations.append({'name': '?d?d?s + word', 'prepend': '?d?d?s', 'append': ''})
    variations.append({'name': '?s?d?d + word', 'prepend': '?s?d?d', 'append': ''})
    variations.append({'name': '?s + word + ?d?d', 'prepend': '?s', 'append': '?d?d', 'two_sided': True})
    variations.append({'name': '?d?d + word + ?s', 'prepend': '?d?d', 'append': '?s', 'two_sided': True})

    # ========================================================================
    # Keyspace: 10,000W
    # Four digits (FULL BRUTE FORCE) or ?d?d+word+?d?d two-sided
    # ========================================================================

    variations.append({'name': '?d?d?d?d append', 'prepend': '', 'append': '?d?d?d?d'})
    variations.append({'name': '?d?d?d?d prepend', 'prepend': '?d?d?d?d', 'append': ''})
    variations.append({'name': '?d?d + word + ?d?d', 'prepend': '?d?d', 'append': '?d?d', 'two_sided': True})

    # ========================================================================
    # Keyspace: 10,890W
    # Two symbols + two digits or symbol + digit + two symbols two-sided
    # ========================================================================

    variations.append({'name': '?s?s + word + ?d?d', 'prepend': '?s?s', 'append': '?d?d', 'two_sided': True})
    variations.append({'name': '?s + word + ?d?d?s', 'prepend': '?s', 'append': '?d?d?s', 'two_sided': True})

    # ========================================================================
    # Keyspace: 3,300W
    # digit-symbol-digit pattern
    # ========================================================================

    variations.append({'name': 'word + ?d?s?d', 'prepend': '', 'append': '?d?s?d'})

    # ========================================================================
    # Keyspace: 33,000W
    # 3-digit + symbol or symbol + 3-digit two-sided
    # ========================================================================

    variations.append({'name': 'word + ?d?d?d?s', 'prepend': '', 'append': '?d?d?d?s'})
    variations.append({'name': 'word + ?s?d?d?d', 'prepend': '', 'append': '?s?d?d?d'})
    variations.append({'name': '?d?d?d?s + word', 'prepend': '?d?d?d?s', 'append': ''})
    variations.append({'name': '?s?d?d?d + word', 'prepend': '?s?d?d?d', 'append': ''})
    variations.append({'name': '?s + word + ?d?d?d', 'prepend': '?s', 'append': '?d?d?d', 'two_sided': True})
    variations.append({'name': '?d?d?d + word + ?s', 'prepend': '?d?d?d', 'append': '?s', 'two_sided': True})

    return variations


def generate_coverage2_attacks():
    """
    Coverage Level 2: Extended mask variations (63 attacks) ordered by keyspace

    Includes ALL Coverage 1 attacks (36) plus additional hybrid patterns (27):
    - Mixed 3-char patterns (?d?s?d, ?s?s?d, ?d?s?s, ?s?d?s)
    - Mixed 4-char patterns (?d?s?d?d, ?d?d?s?s, ?d?s?d?s, ?s?d?d?s, ?s?d?s?d)
    - More two-sided combinations with symbols
    - Multi-symbol two-sided patterns

    Ordered by total keyspace (wordlist_size × combinations) for actual speed
    For same keyspace, ordered by likelihood: Append (3x) > Prepend (1x) > Two-sided (0.5x)

    Expected crack rate: ~92-95% on common passwords
    Estimated time: 8-12 hours on typical hardware
    """
    # Start with all Coverage 1 attacks (36 attacks)
    variations = generate_coverage1_attacks()

    # Add unique Coverage 2 attacks (27 additional attacks)
    variations.append({'name': '?d?s?d + word', 'prepend': '?d?s?d', 'append': ''})
    variations.append({'name': '?d + word + ?d?d?d', 'prepend': '?d', 'append': '?d?d?d', 'two_sided': True})
    variations.append({'name': 'word + ?d?s?s', 'prepend': '', 'append': '?d?s?s'})
    variations.append({'name': 'word + ?s?d?s', 'prepend': '', 'append': '?s?d?s'})
    variations.append({'name': 'word + ?s?s?d', 'prepend': '', 'append': '?s?s?d'})
    variations.append({'name': '?d?s?s + word', 'prepend': '?d?s?s', 'append': ''})
    variations.append({'name': '?s?s?d + word', 'prepend': '?s?s?d', 'append': ''})
    variations.append({'name': '?s + word + ?d?s', 'prepend': '?s', 'append': '?d?s', 'two_sided': True})
    variations.append({'name': '?d + word + ?s?s', 'prepend': '?d', 'append': '?s?s', 'two_sided': True})
    variations.append({'name': 'word + ?d?s?d?d', 'prepend': '', 'append': '?d?s?d?d'})
    variations.append({'name': '?d?s?d?d + word', 'prepend': '?d?s?d?d', 'append': ''})
    variations.append({'name': '?d?d + word + ?d?s', 'prepend': '?d?d', 'append': '?d?s', 'two_sided': True})
    variations.append({'name': '?d + word + ?d?d?s', 'prepend': '?d', 'append': '?d?d?s', 'two_sided': True})
    variations.append({'name': '?d + word + ?s?d?d', 'prepend': '?d', 'append': '?s?d?d', 'two_sided': True})
    variations.append({'name': '?s + word + ?s?s', 'prepend': '?s', 'append': '?s?s', 'two_sided': True})
    variations.append({'name': 'word + ?d?d?s?s', 'prepend': '', 'append': '?d?d?s?s'})
    variations.append({'name': 'word + ?d?s?d?s', 'prepend': '', 'append': '?d?s?d?s'})
    variations.append({'name': 'word + ?s?d?d?s', 'prepend': '', 'append': '?s?d?d?s'})
    variations.append({'name': 'word + ?s?d?s?d', 'prepend': '', 'append': '?s?d?s?d'})
    variations.append({'name': '?d?d?s?s + word', 'prepend': '?d?d?s?s', 'append': ''})
    variations.append({'name': '?d?s + word + ?d?s', 'prepend': '?d?s', 'append': '?d?s', 'two_sided': True})
    variations.append({'name': '?d?s + word + ?s?d', 'prepend': '?d?s', 'append': '?s?d', 'two_sided': True})
    variations.append({'name': '?d?d + word + ?s?s', 'prepend': '?d?d', 'append': '?s?s', 'two_sided': True})
    variations.append({'name': '?d + word + ?d?s?s', 'prepend': '?d', 'append': '?d?s?s', 'two_sided': True})
    variations.append({'name': '?s + word + ?d?s?s', 'prepend': '?s', 'append': '?d?s?s', 'two_sided': True})
    variations.append({'name': '?d?s + word + ?s?s', 'prepend': '?d?s', 'append': '?s?s', 'two_sided': True})
    variations.append({'name': '?d + word + ?s?s?s', 'prepend': '?d', 'append': '?s?s?s', 'two_sided': True})

    return variations


def generate_coverage3_attacks():
    """
    Coverage Level 3: Comprehensive mask variations (134 attacks) ordered by keyspace

    Includes ALL Coverage 1+2 attacks (63) plus exhaustive patterns (71):
    - All 2-char hybrid permutations (?d?s, ?s?d, ?s?s)
    - All 3-char hybrid permutations (?d?s?d, ?s?d?s, ?d?d?s, etc.)
    - All 4-char hybrid permutations
    - Extensive two-sided combinations (68 two-sided attacks)
    - Multi-symbol patterns (?s?s, ?s?s?s, ?s?s?s?s)
    - 5-char masks (4 digits + 1 symbol: ?d?d?d?d?s, ?s?d?d?d?d)

    Ordered by total keyspace (wordlist_size × combinations) for actual speed
    For same keyspace, ordered by likelihood: Append (3x) > Prepend (1x) > Two-sided (0.5x)

    Expected crack rate: ~95-98% on common passwords
    Estimated time: 24+ hours on typical hardware
    """
    # Start with all Coverage 2 attacks (63 attacks = 36 from C1 + 27 from C2)
    variations = generate_coverage2_attacks()

    # Add unique Coverage 3 attacks (71 additional attacks)
    variations.append({'name': '?s?s append', 'prepend': '', 'append': '?s?s'})
    variations.append({'name': '?s?s prepend', 'prepend': '?s?s', 'append': ''})
    variations.append({'name': '?d + word + ?d?s', 'prepend': '?d', 'append': '?d?s', 'two_sided': True})
    variations.append({'name': '?d + word + ?s?d', 'prepend': '?d', 'append': '?s?d', 'two_sided': True})
    variations.append({'name': '?d?s + word + ?d', 'prepend': '?d?s', 'append': '?d', 'two_sided': True})
    variations.append({'name': '?s?d + word + ?d', 'prepend': '?s?d', 'append': '?d', 'two_sided': True})
    variations.append({'name': '?d?d?d + word + ?d', 'prepend': '?d?d?d', 'append': '?d', 'two_sided': True})
    variations.append({'name': '?s?d?s + word', 'prepend': '?s?d?s', 'append': ''})
    variations.append({'name': '?s + word + ?s?d', 'prepend': '?s', 'append': '?s?d', 'two_sided': True})
    variations.append({'name': '?d?s + word + ?s', 'prepend': '?d?s', 'append': '?s', 'two_sided': True})
    variations.append({'name': '?s?d + word + ?s', 'prepend': '?s?d', 'append': '?s', 'two_sided': True})
    variations.append({'name': '?s?s + word + ?d', 'prepend': '?s?s', 'append': '?d', 'two_sided': True})
    variations.append({'name': 'word + ?d?d?s?d', 'prepend': '', 'append': '?d?d?s?d'})
    variations.append({'name': '?d?d?s?d + word', 'prepend': '?d?d?s?d', 'append': ''})
    variations.append({'name': '?d?d + word + ?s?d', 'prepend': '?d?d', 'append': '?s?d', 'two_sided': True})
    variations.append({'name': '?d?s + word + ?d?d', 'prepend': '?d?s', 'append': '?d?d', 'two_sided': True})
    variations.append({'name': '?s?d + word + ?d?d', 'prepend': '?s?d', 'append': '?d?d', 'two_sided': True})
    variations.append({'name': '?d + word + ?d?s?d', 'prepend': '?d', 'append': '?d?s?d', 'two_sided': True})
    variations.append({'name': '?d?d?s + word + ?d', 'prepend': '?d?d?s', 'append': '?d', 'two_sided': True})
    variations.append({'name': '?d?s?d + word + ?d', 'prepend': '?d?s?d', 'append': '?d', 'two_sided': True})
    variations.append({'name': '?s?d?d + word + ?d', 'prepend': '?s?d?d', 'append': '?d', 'two_sided': True})
    variations.append({'name': '?s?s?s append', 'prepend': '', 'append': '?s?s?s'})
    variations.append({'name': '?s?s?s prepend', 'prepend': '?s?s?s', 'append': ''})
    variations.append({'name': '?s?s + word + ?s', 'prepend': '?s?s', 'append': '?s', 'two_sided': True})
    variations.append({'name': 'word + ?d?s?s?d', 'prepend': '', 'append': '?d?s?s?d'})
    variations.append({'name': 'word + ?s?s?d?d', 'prepend': '', 'append': '?s?s?d?d'})
    variations.append({'name': '?d?s?d?s + word', 'prepend': '?d?s?d?s', 'append': ''})
    variations.append({'name': '?d?s?s?d + word', 'prepend': '?d?s?s?d', 'append': ''})
    variations.append({'name': '?s?d?d?s + word', 'prepend': '?s?d?d?s', 'append': ''})
    variations.append({'name': '?s?d?s?d + word', 'prepend': '?s?d?s?d', 'append': ''})
    variations.append({'name': '?s?s?d?d + word', 'prepend': '?s?s?d?d', 'append': ''})
    variations.append({'name': '?s?d + word + ?d?s', 'prepend': '?s?d', 'append': '?d?s', 'two_sided': True})
    variations.append({'name': '?s?d + word + ?s?d', 'prepend': '?s?d', 'append': '?s?d', 'two_sided': True})
    variations.append({'name': '?d + word + ?s?d?s', 'prepend': '?d', 'append': '?s?d?s', 'two_sided': True})
    variations.append({'name': '?d + word + ?s?s?d', 'prepend': '?d', 'append': '?s?s?d', 'two_sided': True})
    variations.append({'name': '?s + word + ?d?s?d', 'prepend': '?s', 'append': '?d?s?d', 'two_sided': True})
    variations.append({'name': '?s + word + ?s?d?d', 'prepend': '?s', 'append': '?s?d?d', 'two_sided': True})
    variations.append({'name': '?d?d?s + word + ?s', 'prepend': '?d?d?s', 'append': '?s', 'two_sided': True})
    variations.append({'name': '?d?s?d + word + ?s', 'prepend': '?d?s?d', 'append': '?s', 'two_sided': True})
    variations.append({'name': '?d?s?s + word + ?d', 'prepend': '?d?s?s', 'append': '?d', 'two_sided': True})
    variations.append({'name': '?s?d?d + word + ?s', 'prepend': '?s?d?d', 'append': '?s', 'two_sided': True})
    variations.append({'name': '?s?d?s + word + ?d', 'prepend': '?s?d?s', 'append': '?d', 'two_sided': True})
    variations.append({'name': '?s?s?d + word + ?d', 'prepend': '?s?s?d', 'append': '?d', 'two_sided': True})
    variations.append({'name': 'word + ?d?s?s?s', 'prepend': '', 'append': '?d?s?s?s'})
    variations.append({'name': 'word + ?s?d?s?s', 'prepend': '', 'append': '?s?d?s?s'})
    variations.append({'name': 'word + ?s?s?d?s', 'prepend': '', 'append': '?s?s?d?s'})
    variations.append({'name': 'word + ?s?s?s?d', 'prepend': '', 'append': '?s?s?s?d'})
    variations.append({'name': '?d?s?s?s + word', 'prepend': '?d?s?s?s', 'append': ''})
    variations.append({'name': '?s?d?s?s + word', 'prepend': '?s?d?s?s', 'append': ''})
    variations.append({'name': '?s?s?d?s + word', 'prepend': '?s?s?d?s', 'append': ''})
    variations.append({'name': '?s?s?s?d + word', 'prepend': '?s?s?s?d', 'append': ''})
    variations.append({'name': '?s?d + word + ?s?s', 'prepend': '?s?d', 'append': '?s?s', 'two_sided': True})
    variations.append({'name': '?s?s + word + ?d?s', 'prepend': '?s?s', 'append': '?d?s', 'two_sided': True})
    variations.append({'name': '?s?s + word + ?s?d', 'prepend': '?s?s', 'append': '?s?d', 'two_sided': True})
    variations.append({'name': '?s + word + ?s?d?s', 'prepend': '?s', 'append': '?s?d?s', 'two_sided': True})
    variations.append({'name': '?s + word + ?s?s?d', 'prepend': '?s', 'append': '?s?s?d', 'two_sided': True})
    variations.append({'name': '?d?s?s + word + ?s', 'prepend': '?d?s?s', 'append': '?s', 'two_sided': True})
    variations.append({'name': '?s?d?s + word + ?s', 'prepend': '?s?d?s', 'append': '?s', 'two_sided': True})
    variations.append({'name': '?s?s?d + word + ?s', 'prepend': '?s?s?d', 'append': '?s', 'two_sided': True})
    variations.append({'name': '?s?s?s + word + ?d', 'prepend': '?s?s?s', 'append': '?d', 'two_sided': True})
    variations.append({'name': 'word + ?s?s?s?s', 'prepend': '', 'append': '?s?s?s?s'})
    variations.append({'name': '?s?s?s?s + word', 'prepend': '?s?s?s?s', 'append': ''})
    variations.append({'name': '?s?s + word + ?s?s', 'prepend': '?s?s', 'append': '?s?s', 'two_sided': True})
    variations.append({'name': '?s + word + ?s?s?s', 'prepend': '?s', 'append': '?s?s?s', 'two_sided': True})
    variations.append({'name': '?s?s?s + word + ?s', 'prepend': '?s?s?s', 'append': '?s', 'two_sided': True})

    # ========================================================================
    # Keyspace: 330,000W
    # 5-character masks: 4 digits + 1 symbol (very large keyspace, lower priority)
    # ========================================================================

    variations.append({'name': 'word + ?d?d?d?d?s', 'prepend': '', 'append': '?d?d?d?d?s'})
    variations.append({'name': 'word + ?s?d?d?d?d', 'prepend': '', 'append': '?s?d?d?d?d'})
    variations.append({'name': '?d?d?d?d?s + word', 'prepend': '?d?d?d?d?s', 'append': ''})
    variations.append({'name': '?s?d?d?d?d + word', 'prepend': '?s?d?d?d?d', 'append': ''})
    variations.append({'name': '?d?d?d?d + word + ?s', 'prepend': '?d?d?d?d', 'append': '?s', 'two_sided': True})
    variations.append({'name': '?s + word + ?d?d?d?d', 'prepend': '?s', 'append': '?d?d?d?d', 'two_sided': True})

    return variations


def apply_case_variations(word, toggle_depths=None):
    """
    Apply simplified case variations to a single word.
    Includes: original, lower, upper, capitalize (sentence case), Title Case, and toggle variations.
    No PascalCase or wordninja - simplified for password patterns.

    Args:
        word: Single word to transform
        toggle_depths: Set of toggle depths to apply (e.g., {1}, {2}, {1,2,3}). Empty set or None for no toggles.

    Returns:
        Set of case variations
    """
    if toggle_depths is None:
        toggle_depths = set()  # No toggles by default if not specified
    # Try to import titlecase library
    try:
        from titlecase import titlecase
        has_titlecase = True
    except ImportError:
        has_titlecase = False

    variations = set()

    # Always include original
    variations.add(word)

    # All lowercase
    variations.add(word.lower())

    # All uppercase
    variations.add(word.upper())

    # Capitalize / Sentence case (first letter upper, rest lower)
    variations.add(word.capitalize())

    # Title Case (capitalize each word after spaces using titlecase library)
    if ' ' in word:
        if has_titlecase:
            variations.add(titlecase(word))
        else:
            variations.add(word.title())  # Fallback to built-in

    # Toggle case variations (configurable depth within first 15 chars)
    # Matches NCL-cracking toggles3.rule behavior
    if toggle_depths:
        max_toggle_pos = min(len(word), 15)

        # 1-character toggles: C(15,1) = 15
        if 1 in toggle_depths and max_toggle_pos >= 1:
            for positions in itertools.combinations(range(max_toggle_pos), 1):
                chars = list(word.lower())
                for pos in positions:
                    if chars[pos].isalpha():
                        chars[pos] = chars[pos].upper()
                variations.add(''.join(chars))

        # 2-character toggles: C(15,2) = 105
        if 2 in toggle_depths and max_toggle_pos >= 2:
            for positions in itertools.combinations(range(max_toggle_pos), 2):
                chars = list(word.lower())
                for pos in positions:
                    if chars[pos].isalpha():
                        chars[pos] = chars[pos].upper()
                variations.add(''.join(chars))

        # 3-character toggles: C(15,3) = 455
        if 3 in toggle_depths and max_toggle_pos >= 3:
            for positions in itertools.combinations(range(max_toggle_pos), 3):
                chars = list(word.lower())
                for pos in positions:
                    if chars[pos].isalpha():
                        chars[pos] = chars[pos].upper()
                variations.add(''.join(chars))

    return variations


def apply_separator_transformations(words, separators):
    """
    Apply separator transformations to a list of words.
    Handles space, hyphen, underscore, and period replacement.

    Args:
        words: List of words to transform
        separators: List of separator strings ['_', '-', 'none', ' ']

    Returns:
        Set of transformed words
    """
    results = set()

    for word in words:
        # Always add original
        results.add(word)

        # Only process words with separators
        if has_separator(word):
            for sep in separators:
                if sep == 'none' or sep == '':
                    # Remove all separators
                    results.add(replace_separators(word))
                elif sep == ' ':
                    # Keep original separators (already added as original)
                    pass
                else:
                    # Replace all separators with specified separator (_, -, etc.)
                    results.add(replace_separators(word, sep))

    return results


def generate_selective_leet(word, max_subs=None):
    """
    Generate all possible selective leetspeak variations while preserving original case.

    Args:
        word: Base word to transform (case preserved)
        max_subs: Maximum number of substitutions (None = all)

    Returns:
        Set of all leet variations
    """
    # Leet substitution map (lowercase keys)
    LEET_MAP = {
        'a': ['a', '@', '4'],
        'e': ['e', '3'],
        'i': ['i', '1', '!'],
        'o': ['o', '0'],
        's': ['s', '5', '$'],
        'l': ['l', '1'],
        't': ['t', '7'],
        'g': ['g', '9'],
        'b': ['b', '8'],
        'z': ['z', '2'],
    }

    variations = set()

    # Always add original word without any leet substitutions
    variations.add(word)

    # Find all positions that can be substituted (case-insensitive matching)
    sub_positions = []
    for i, char in enumerate(word):
        char_lower = char.lower()
        if char_lower in LEET_MAP:
            sub_positions.append((i, char_lower, LEET_MAP[char_lower]))

    if not sub_positions:
        return {word}

    # Generate all combinations of substitutions
    for indices in range(1, len(sub_positions) + 1):  # Start from 1 to skip no-substitution case (already added)
        if max_subs and indices > max_subs:
            break

        # Choose which positions to substitute
        for combo in itertools.combinations(range(len(sub_positions)), indices):
            # Get all possible character choices for selected positions
            choices = []
            for idx in combo:
                pos, original_char, variants = sub_positions[idx]
                # Only include variants that are different from original
                choices.append([(pos, v) for v in variants if v != original_char])

            if not choices:
                continue

            # Generate all combinations of variant choices
            for choice_combo in itertools.product(*choices):
                chars = list(word)  # Preserve original case
                for pos, variant in choice_combo:
                    chars[pos] = variant
                variations.add(''.join(chars))

    return variations


def apply_case_transformations_leet(word):
    """
    Apply various case transformations including toggle patterns.
    Optimized

    Returns:
        Set of case variations
    """
    # Try to import wordninja for compound word splitting (PascalCase)
    try:
        import wordninja
        has_wordninja = True
    except ImportError:
        has_wordninja = False

    # Try to import titlecase for proper title casing
    try:
        from titlecase import titlecase
        has_titlecase = True
    except ImportError:
        has_titlecase = False

    variations = set()

    # Original
    variations.add(word)

    # All lowercase
    variations.add(word.lower())

    # All uppercase
    variations.add(word.upper())

    # Capitalize first (sentence case)
    variations.add(word.capitalize())

    # Title case (use titlecase library if available, otherwise built-in)
    if has_titlecase:
        variations.add(titlecase(word))
    else:
        variations.add(word.title())

    # PascalCase (each word segment capitalized, no spaces)
    if ' ' in word:
        # Words with spaces
        segments = word.split()
        pascal_word = ''.join([seg.capitalize() for seg in segments])
        variations.add(pascal_word)
    elif has_wordninja and len(word) > 3:
        # Compound words - use wordninja
        try:
            segments = wordninja.split(word)
            if len(segments) > 1:
                pascal_word = ''.join([seg.capitalize() for seg in segments])
                variations.add(pascal_word)
        except:
            pass

    # Toggle cases
    # This generates C(12,3) = 220 variations for words >= 12 chars
    max_toggle_pos = min(len(word), 12)
    if max_toggle_pos >= 3:
        for positions in itertools.combinations(range(max_toggle_pos), 3):
            chars = list(word.lower())
            for pos in positions:
                chars[pos] = chars[pos].upper()
            variations.add(''.join(chars))

    # Also add simple single-char toggles (first 4) for shorter passwords
    for i in range(min(len(word), 4)):
        chars = list(word.lower())
        chars[i] = chars[i].upper()
        variations.add(''.join(chars))

    # Every other uppercase (offset 0)
    chars = list(word.lower())
    for i in range(0, len(chars), 2):
        chars[i] = chars[i].upper()
    variations.add(''.join(chars))

    # Every other uppercase (offset 1)
    chars = list(word.lower())
    for i in range(1, len(chars), 2):
        chars[i] = chars[i].upper()
    variations.add(''.join(chars))

    return variations


def generate_all_variations(word, max_leet_subs=None, include_case=True):
    """
    Generate all leetspeak + case variations

    Args:
        word: Base word
        max_leet_subs: Max number of leet substitutions (None = unlimited)
        include_case: Apply case transformations (including toggles)

    Returns:
        Set of all variations
    """
    all_variations = set()

    # Generate leetspeak variations
    leet_variations = generate_selective_leet(word, max_subs=max_leet_subs)

    # Apply case transformations to each leet variation
    if include_case:
        for leet_var in leet_variations:
            case_variations = apply_case_transformations_leet(leet_var)
            all_variations.update(case_variations)
    else:
        all_variations = leet_variations

    return all_variations


def apply_selective_leetspeak(words, max_subs):
    """
    Apply selective leetspeak with case transformations

    Args:
        words: List of words to transform
        max_subs: Maximum number of leet substitutions per word

    Returns:
        Set of leet + case variations
    """
    results = set()

    for word in words:
        # Generate all leet + case variations for this word
        variations = generate_all_variations(word, max_leet_subs=max_subs, include_case=True)
        results.update(variations)

    return results


def clean_word(word):
    """
    Clean a word by removing diacritics, special characters, and normalizing.
    Preserves spaces for separator processing.
    Based on word-reaper's cleaner.py

    Args:
        word: Word to clean

    Returns:
        Cleaned word (lowercase, no diacritics, no special chars except spaces)
    """
    import unicodedata
    import re

    # Normalize Unicode (decompose characters like é → e + ´)
    word = unicodedata.normalize('NFKD', word)

    # Remove combining characters (diacritics/accents)
    word = ''.join([c for c in word if not unicodedata.combining(c)])

    # Convert to lowercase
    word = word.lower()

    # Remove special characters (keep only alphanumeric and spaces)
    word = re.sub(r'[^a-z0-9 ]', '', word)

    return word


def preprocess_wordlist(input_path, output_path, case_options=None, separators=None,
                       selective_leet_max=None, no_leet=False, log_file=None):
    """
    Preprocess a wordlist with 2-phase transformation pipeline:
    Phase 1: Preserve original formatting (symbols/diacritics) → case → separators → leet
    Phase 2: Clean (remove symbols/diacritics, preserve case) → case → separators → leet

    Args:
        input_path: Input wordlist path
        output_path: Output wordlist path
        case_options: List of case transformations (deprecated - always applies all)
        separators: List of separator transformations ['_', '-', 'none', ' ']
        selective_leet_max: Max leet substitutions (None = disabled, 0 = unlimited)
        no_leet: Skip all leet preprocessing (overrides selective_leet_max)
        log_file: Log file for messages

    Returns:
        Number of words generated, or None on error
    """
    try:
        # Read input words (original formatting preserved)
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            original_words = [line.strip() for line in f if line.strip()]

        original_count = len(original_words)
        results = set()

        log_message(f"Starting 2-phase preprocessing on {original_count} words", log_file)

        # === PHASE 1: Preserve Original Formatting (symbols/diacritics intact) ===
        log_message(f"--- Phase 1: Preserving original formatting ---", log_file)

        for word in original_words:
            # Step 1: Apply case variations (including original)
            case_vars = apply_case_variations(word)

            # Step 2: Apply separators to EACH case variation
            for case_var in case_vars:
                sep_results = apply_separator_transformations({case_var}, separators) if separators else {case_var}

                # Step 3: Apply selective leet to EACH case+separator result (skip if --no-leet)
                if not no_leet and selective_leet_max is not None:
                    for sep_var in sep_results:
                        leet_results = generate_selective_leet(sep_var, selective_leet_max)
                        results.update(leet_results)
                else:
                    results.update(sep_results)

        log_message(f"After Phase 1: {len(results)} words", log_file)

        # === PHASE 2: Cleaned Version (remove symbols/diacritics, preserve case) ===
        log_message(f"--- Phase 2: Cleaning and transforming ---", log_file)

        cleaned_words = set()
        for word in original_words:
            cleaned = clean_word(word)
            if cleaned and len(cleaned) > 0:
                cleaned_words.add(cleaned)

        log_message(f"Cleaned: {len(cleaned_words)} unique words", log_file)

        for word in cleaned_words:
            # Step 1: Apply case variations (including original)
            case_vars = apply_case_variations(word)

            # Step 2: Apply separators to EACH case variation
            for case_var in case_vars:
                sep_results = apply_separator_transformations({case_var}, separators) if separators else {case_var}

                # Step 3: Apply selective leet to EACH case+separator result (skip if --no-leet)
                if not no_leet and selective_leet_max is not None:
                    for sep_var in sep_results:
                        leet_results = generate_selective_leet(sep_var, selective_leet_max)
                        results.update(leet_results)
                else:
                    results.update(sep_results)

        log_message(f"After Phase 2: {len(results)} total words", log_file)

        # Write output (deduplicated by set)
        with open(output_path, 'w', encoding='utf-8') as f:
            for word in sorted(results):
                f.write(f"{word}\n")

        multiplier = len(results) / original_count if original_count > 0 else 1
        log_message(f"Preprocessing complete: {original_count} -> {len(results)} words ({multiplier:.1f}x)", log_file)

        return len(results)

    except Exception as e:
        log_message(f"{CYAN}[!] Preprocessing error: {e}{RESET}", log_file)
        import traceback
        traceback.print_exc()
        return None


def get_cached_wordlist_path(base_wordlist, cache_dir, case_options, separators, selective_leet_max):
    """
    Generate a cache filename based on preprocessing options.

    Returns:
        Path to cached wordlist
    """
    base_name = os.path.basename(base_wordlist)
    name_without_ext, ext = os.path.splitext(base_name)

    # Simple naming: basename_preprocessed.txt
    cache_filename = f"{name_without_ext}_preprocessed{ext}"
    return os.path.join(cache_dir, cache_filename)


def process_wordlist_with_variations(args, base_wordlist_path, base_wordlist_name,
                                     variations, rule_files, output_dir,
                                     total_cracked, phase_name, intermediate_wordlists=None, temp_dir=None):
    """Process a base wordlist with all mask variations

    Optimized to:
    - Process single-sided attacks directly with hybrid mode
    - Group two-sided attacks by shared intermediate wordlist
    - Reuse intermediate wordlists for multiple attacks
    - Use pre-created intermediates when available

    Args:
        intermediate_wordlists: Dict mapping intermediate keys to file paths (optional)
    """
    attempts = 0
    skipped = 0

    # Ensure temp_dir is set
    if temp_dir is None:
        temp_dir = get_optimal_temp_dir()

    # Get total hash count for progress display
    total_hashes = count_hash_lines(args.hash_file)

    if not _quiet_mode:
            print()
    log_message(f"--- {phase_name} ---", args.log_file)

    # Process attacks in order (preserving keyspace ordering)
    # Handle both single-sided and two-sided inline
    for variation in variations:
        var_name = variation['name']
        prepend_mask = variation.get('prepend', '')
        append_mask = variation.get('append', '')
        is_two_sided = variation.get('two_sided', False)

        # === Handle single-sided attacks ===
        if not is_two_sided:
            # Determine attack mode
            if append_mask and not prepend_mask:
                attack_mode = 6  # Append-only
                mask = append_mask
            elif prepend_mask and not append_mask:
                attack_mode = 7  # Prepend-only
                mask = prepend_mask
            else:
                continue  # Skip invalid patterns

            # Use hybrid attack mode directly (NO temp file generation!)
            if not _quiet_mode:
                    print()
            log_message(f"Attempting: {base_wordlist_name} + {var_name}", args.log_file)

            # Show interactive prompt before first attack
            show_interactive_prompt()

            # If --force, use single-pass with forced -O, otherwise use smart two-pass
            if args.force:
                result = run_hashcat_attack_single(
                    args.hashcat_bin, args.hash_file, args.hash_mode,
                    base_wordlist_path, output_dir,
                    timeout_hours=args.max_time,
                    workload=args.workload, use_optimized=True,  # Force -O
                    slow_candidates=args.slow_candidates,
                    attack_mode=attack_mode, mask=mask
                )
            else:
                result = run_hashcat_attack(
                    args.hashcat_bin, args.hash_file, args.hash_mode,
                    base_wordlist_path, output_dir, timeout_hours=args.max_time,
                    workload=args.workload, optimize_kernels=args.optimize_kernels,
                    slow_candidates=args.slow_candidates,
                    attack_mode=attack_mode, mask=mask
                )

            # Reset attack-specific flags after each attack
            _session_control.reset_attack_flags()

            # Get newly cracked hashes (not in total_cracked yet)
            newly_cracked = {h: p for h, p in result['cracked'].items() if h not in total_cracked}
            new_cracks = len(newly_cracked)
            record_crack_timestamps(newly_cracked)
            total_cracked.update(result['cracked'])
            log_message(f"Completed in {result['elapsed_hours']:.2f}h | {format_crack_count(new_cracks, len(total_cracked), newly_cracked, total_hashes)}", args.log_file)

            # Still log to file separately
            for hash_val, plaintext in newly_cracked.items():
                log_cracked(hash_val, plaintext, args.log_file)

            attempts += 1

            # Check if all hashes have been cracked
            if len(total_cracked) == total_hashes:
                return attempts, skipped

            # Check if session should stop
            if _session_control.should_kill() or _session_control.should_finish():
                return attempts, skipped

            continue

        # === Handle two-sided attacks ===
        # Determine strategy: use mask with lowest keyspace to create intermediate
        smaller_mask, larger_mask, use_prepend_first = determine_optimal_two_sided_strategy(
            prepend_mask, append_mask
        )

        hybrid_mode = 6 if use_prepend_first else 7  # 6=append, 7=prepend

        # If --force is used, skip all splitting and just use -O on everything
        if args.force:
            # Generate intermediate from full wordlist
            if use_prepend_first:
                est_size = estimate_masked_wordlist_size(base_wordlist_path, smaller_mask, '')
            else:
                est_size = estimate_masked_wordlist_size(base_wordlist_path, '', smaller_mask)

            if est_size > args.max_size:
                if not _quiet_mode:
                        print()
                log_message(f"Skipping attack: intermediate wordlist too large ({est_size:.1f}MB)", args.log_file)
                skipped += 1
                continue

            if not _quiet_mode:
                    print()
            if use_prepend_first:
                log_message(f"Generating intermediate: {smaller_mask} + word ({est_size:.1f}MB est.)", args.log_file)
                intermediate_wordlist = generate_masked_wordlist(
                    base_wordlist_path, smaller_mask, '', temp_dir, debug=args.debug,
                    hashcat_bin=args.hashcat_bin
                )
            else:
                log_message(f"Generating intermediate: word + {smaller_mask} ({est_size:.1f}MB est.)", args.log_file)
                intermediate_wordlist = generate_masked_wordlist(
                    base_wordlist_path, '', smaller_mask, temp_dir, debug=args.debug,
                    hashcat_bin=args.hashcat_bin
                )

            if not intermediate_wordlist or not os.path.exists(intermediate_wordlist):
                log_message(f"{CYAN}[!] Failed to generate intermediate wordlist{RESET}", args.log_file)
                skipped += 1
                continue

            # Execute single-pass attack with forced -O
            if not _quiet_mode:
                    print()
            log_message(f"Attempting: {var_name} (mode {hybrid_mode} + {larger_mask})", args.log_file)
            show_interactive_prompt()

            result = run_hashcat_attack_single(
                args.hashcat_bin, args.hash_file, args.hash_mode,
                intermediate_wordlist, output_dir,
                timeout_hours=args.max_time,
                workload=args.workload, use_optimized=True,  # Force -O
                slow_candidates=args.slow_candidates,
                attack_mode=hybrid_mode, mask=larger_mask
            )

        else:
            # Normal mode: try upstream splitting first (generate from pre-split sources)
            safe_intermediate = None
            unsafe_intermediate = None

            if intermediate_wordlists and args.optimize_kernels:
                # Attempt to generate intermediates from pre-split sources
                safe_intermediate, unsafe_intermediate = generate_intermediate_from_presplit(
                    base_wordlist_path, smaller_mask, larger_mask, use_prepend_first,
                    args.hash_mode, temp_dir, debug=args.debug,
                    hashcat_bin=args.hashcat_bin
                )

            # Fallback: generate from full wordlist if upstream splitting failed
            if safe_intermediate is None and unsafe_intermediate is None:
                # Estimate size
                if use_prepend_first:
                    est_size = estimate_masked_wordlist_size(base_wordlist_path, smaller_mask, '')
                else:
                    est_size = estimate_masked_wordlist_size(base_wordlist_path, '', smaller_mask)

                if est_size > args.max_size:
                    if not _quiet_mode:
                            print()
                    log_message(f"Skipping attack: intermediate wordlist too large ({est_size:.1f}MB)", args.log_file)
                    skipped += 1
                    continue

                # Generate intermediate wordlist from full base
                if not _quiet_mode:
                        print()
                if use_prepend_first:
                    log_message(f"Generating intermediate: {smaller_mask} + word ({est_size:.1f}MB est.)", args.log_file)
                    intermediate_wordlist = generate_masked_wordlist(
                        base_wordlist_path, smaller_mask, '', temp_dir, debug=args.debug,
                        hashcat_bin=args.hashcat_bin
                    )
                else:
                    log_message(f"Generating intermediate: word + {smaller_mask} ({est_size:.1f}MB est.)", args.log_file)
                    intermediate_wordlist = generate_masked_wordlist(
                        base_wordlist_path, '', smaller_mask, temp_dir, debug=args.debug,
                        hashcat_bin=args.hashcat_bin
                    )

                if not intermediate_wordlist or not os.path.exists(intermediate_wordlist):
                    log_message(f"{CYAN}[!] Failed to generate intermediate wordlist{RESET}", args.log_file)
                    skipped += 1
                    continue

                # Execute single-pass attack with full intermediate
                if not _quiet_mode:
                        print()
                log_message(f"Attempting: {var_name} (mode {hybrid_mode} + {larger_mask})", args.log_file)
                show_interactive_prompt()

                result = run_hashcat_attack(
                    args.hashcat_bin, args.hash_file, args.hash_mode,
                    intermediate_wordlist, output_dir, timeout_hours=args.max_time,
                    workload=args.workload, optimize_kernels=args.optimize_kernels,
                    slow_candidates=args.slow_candidates,
                    attack_mode=hybrid_mode, mask=larger_mask
                )
            else:
                # Execute two-pass attack with upstream-split intermediates
                if not _quiet_mode:
                        print()
                log_message(f"Attempting: {var_name} (mode {hybrid_mode} + {larger_mask})", args.log_file)

                # Pass 1: Safe intermediate with -O
                if safe_intermediate and os.path.exists(safe_intermediate):
                    if not _quiet_mode:
                        log_message(f"  └─ Pass 1/2: Optimized kernel (upstream split)", args.log_file)
                    show_interactive_prompt()

                    result1 = run_hashcat_attack_single(
                        args.hashcat_bin, args.hash_file, args.hash_mode,
                        safe_intermediate, output_dir,
                        timeout_hours=args.max_time,
                        workload=args.workload, use_optimized=True,
                        slow_candidates=args.slow_candidates,
                        attack_mode=hybrid_mode, mask=larger_mask
                    )
                else:
                    result1 = {'cracked': {}, 'elapsed_hours': 0, 'status': 'skipped'}

                # Pass 2: Unsafe intermediate without -O
                if unsafe_intermediate and os.path.exists(unsafe_intermediate):
                    if not _quiet_mode:
                        log_message(f"  └─ Pass 2/2: Pure kernel (upstream split)", args.log_file)
                    show_interactive_prompt()

                    result2 = run_hashcat_attack_single(
                        args.hashcat_bin, args.hash_file, args.hash_mode,
                        unsafe_intermediate, output_dir,
                        timeout_hours=args.max_time,
                        workload=args.workload, use_optimized=False,
                        slow_candidates=args.slow_candidates,
                        attack_mode=hybrid_mode, mask=larger_mask
                    )

                    # Merge results
                    result1['cracked'].update(result2['cracked'])
                    result1['elapsed_hours'] += result2['elapsed_hours']
                    if result2['status'] != 'completed':
                        result1['status'] = result2['status']

                result = result1

        # Reset attack-specific flags
        _session_control.reset_attack_flags()

        # Get newly cracked hashes (not in total_cracked yet)
        newly_cracked = {h: p for h, p in result['cracked'].items() if h not in total_cracked}
        new_cracks = len(newly_cracked)
        record_crack_timestamps(newly_cracked)
        total_cracked.update(result['cracked'])
        log_message(f"Completed in {result['elapsed_hours']:.2f}h | {format_crack_count(new_cracks, len(total_cracked), newly_cracked, total_hashes)}", args.log_file)

        # Still log to file separately
        for hash_val, plaintext in newly_cracked.items():
            log_cracked(hash_val, plaintext, args.log_file)

        attempts += 1

        # Check if all hashes have been cracked
        if len(total_cracked) == total_hashes:
            return attempts, skipped

        # Check if session should stop
        if _session_control.should_kill() or _session_control.should_finish():
            return attempts, skipped

    return attempts, skipped


def has_separator(word):
    """
    Check if a word contains any common separator character.

    Args:
        word: Word to check

    Returns:
        bool: True if word contains a separator
    """
    separators = [' ', '-', '_', '.']
    return any(sep in word for sep in separators)


def replace_separators(word, new_sep=''):
    """
    Replace all common separators in a word with a new separator.

    Args:
        word: Word to process
        new_sep: New separator to use (empty string removes separators)

    Returns:
        str: Word with separators replaced
    """
    separators = [' ', '-', '_', '.']
    result = word
    for sep in separators:
        result = result.replace(sep, new_sep)
    return result


def build_wordlists_ncl_style(base_wordlist_path, output_dir='wordlists', no_leet=False, toggle_depths=None):
    """
    Build NCL-style split wordlists from a base wordlist.

    Outputs ONLY two files:
    - all_{basename}.txt: all case/separator/toggle variants (no leet)
    - leet_{basename}.txt: selective leet variants NOT in all_{basename}.txt (skipped if no_leet=True)

    Intermediate files are created temporarily then deleted.

    Args:
        base_wordlist_path: Path to base wordlist
        output_dir: Directory to save output wordlists
        no_leet: Skip leet wordlist generation
        toggle_depths: Set of toggle depths to apply (e.g., {1}, {2}, {1,2,3}). Defaults to {2}.
    """
    if toggle_depths is None:
        toggle_depths = {2}  # Default: only 2-char toggles

    log_message(f"Building wordlists from: {os.path.basename(base_wordlist_path)}")

    # Validate input
    if not os.path.exists(base_wordlist_path):
        print(f"{CYAN}[!] Error:{RESET} Base wordlist not found: {base_wordlist_path}")
        sys.exit(1)

    # Get base name without extension
    base_name = os.path.splitext(os.path.basename(base_wordlist_path))[0]

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Temporary directory for intermediates
    temp_dir = tempfile.mkdtemp(prefix='hashgauntlet_build_')

    try:
        # Read base wordlist with encoding handling
        try:
            with open(base_wordlist_path, encoding='utf-8') as f:
                base_words = [line.strip() for line in f if line.strip()]
        except UnicodeDecodeError:
            # Fall back to Latin-1 (handles all byte values)
            with open(base_wordlist_path, encoding='latin-1') as f:
                base_words = [line.strip() for line in f if line.strip()]

        log_message(f"Found {len(base_words)} base words")

        # Add cleaned versions of words (remove diacritics/special chars)
        # This ensures we generate variations for both original and cleaned forms
        cleaned_words = set()
        for word in base_words:
            cleaned = clean_word(word)
            if cleaned and len(cleaned) > 0 and cleaned not in base_words:
                cleaned_words.add(cleaned)

        # Combine original + cleaned words for processing
        all_base_words = set(base_words) | cleaned_words
        log_message(f"Processing {len(all_base_words)} transformed words")

        # Generate all case/separator variants
        log_message(f"Generating case and separator variants...")

        # 1. Generate lowercase with separators
        lowercase_variants = set()
        for word in all_base_words:
            if has_separator(word):
                lowercase_variants.add(word.lower())                       # original separator
                lowercase_variants.add(replace_separators(word.lower()))   # no separator
                lowercase_variants.add(replace_separators(word.lower(), '_'))  # underscore
                lowercase_variants.add(replace_separators(word.lower(), '-'))  # dash
            else:
                lowercase_variants.add(word.lower())

        # 2. Generate titlecase with separators
        titlecase_variants = set()
        for word in all_base_words:
            if has_separator(word):
                titlecase_variants.add(word)                       # original separator
                titlecase_variants.add(replace_separators(word))   # no separator
                titlecase_variants.add(replace_separators(word, '_'))  # underscore
                titlecase_variants.add(replace_separators(word, '-'))  # dash
            else:
                titlecase_variants.add(word)

        # 3. Generate uppercase with separators
        uppercase_variants = set()
        for word in all_base_words:
            if has_separator(word):
                uppercase_variants.add(word.upper())                       # original separator
                uppercase_variants.add(replace_separators(word.upper()))   # no separator
                uppercase_variants.add(replace_separators(word.upper(), '_'))  # underscore
                uppercase_variants.add(replace_separators(word.upper(), '-'))  # dash
            else:
                uppercase_variants.add(word.upper())

        # 4. Generate sentence case with separators
        sentencecase_variants = set()
        for word in all_base_words:
            # Sentence case: first char upper, rest lower
            sentence_word = word[0].upper() + word[1:].lower() if len(word) > 0 else word
            if has_separator(sentence_word):
                sentencecase_variants.add(sentence_word)                       # original separator
                sentencecase_variants.add(replace_separators(sentence_word))   # no separator
                sentencecase_variants.add(replace_separators(sentence_word, '_'))  # underscore
                sentencecase_variants.add(replace_separators(sentence_word, '-'))  # dash
            else:
                sentencecase_variants.add(sentence_word)

        # 5. Generate toggles for ALL separator variants
        toggles_variants = set()
        # Apply toggles to all case variants (lowercase + titlecase + uppercase + sentence)
        all_case_variants = lowercase_variants | titlecase_variants | uppercase_variants | sentencecase_variants

        for word in all_case_variants:
            # apply_case_variations() internally limits to first 15 chars
            toggles = apply_case_variations(word, toggle_depths=toggle_depths)
            toggles_variants.update(toggles)

        # 6. Merge all into all_{basename}.txt
        all_variants = (lowercase_variants | titlecase_variants | uppercase_variants |
                       sentencecase_variants | toggles_variants)

        all_path = f"{output_dir}/all_{base_name}.txt"
        try:
            with open(all_path, 'w', encoding='utf-8', buffering=16384) as f:
                count = 0
                # Write directly without sorting to avoid memory issues
                for word in all_variants:
                    f.write(word + '\n')
                    count += 1
                    # Periodic flush to avoid buffer buildup
                    if count % 50000 == 0:
                        f.flush()
                        gc.collect()  # Release memory
            log_message(f"Created: all_{base_name}.txt ({len(all_variants)} words)")
        except IOError as e:
            log_message(f"Error writing all_{base_name}.txt: {e}")
            raise

        # Free memory immediately
        del all_variants
        gc.collect()

        # 7. Generate selective leet variants (NOT in all.txt) - skip if --no-leet
        if not no_leet:
            log_message(f"Generating selective leetspeak variants...")

            # Write directly to file to avoid memory buildup
            # First pass: collect all_variants into a set for deduplication
            all_words_set = set()
            with open(all_path, 'r', encoding='utf-8', errors='ignore') as f:
                all_words_set = set(line.strip() for line in f)

            leet_path = f"{output_dir}/leet_{base_name}.txt"
            leet_count = 0
            leet_seen = set()  # Track written leet words to prevent duplicates

            try:
                with open(leet_path, 'w', encoding='utf-8', buffering=16384) as f:
                    processed = 0
                    total = len(all_words_set)
                    print_interval = max(1, total // 10)

                    for word in all_words_set:
                        # Generate leet variants for this word
                        leet_words = generate_all_variations(word, max_leet_subs=4, include_case=False)

                        # Write only NEW variants (not in all_words_set AND not already written)
                        for leet_word in leet_words:
                            if leet_word not in all_words_set and leet_word not in leet_seen:
                                f.write(leet_word + '\n')
                                leet_seen.add(leet_word)  # Mark as written
                                leet_count += 1

                        processed += 1
                        # Progress and memory management
                        if processed % print_interval == 0:
                            percent = (processed / total) * 100
                            log_message(f"\rProgress: {percent:.0f}%", end='', flush=True)
                            f.flush()
                            gc.collect()  # Release memory periodically

                # Print newline after progress completes
                if not _quiet_mode:
                    print()

                log_message(f"Created: leet_{base_name}.txt ({leet_count} words)")
            except IOError as e:
                log_message(f"Error writing leet_{base_name}.txt: {e}")
                raise

            # Free memory
            del all_words_set
            del leet_seen
            gc.collect()

    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# AD Credential Auditing - new functions
# ---------------------------------------------------------------------------

def parse_secretsdump(secretsdump_file):
    """
    Parse secretsdump output (username:RID:LMhash:NTLMhash:::) and extract
    NTLM hashes into a temporary hash file.

    Multiple accounts sharing the same NTLM hash (same password) are all
    retained so every affected username appears in the audit report.

    Returns:
        tuple: (hash_file_path, {ntlm_hash: [SAMAccountName, ...]})
    """
    hash_to_users = {}  # {hash: [username, ...]} - preserves all users per hash

    EMPTY_NT = '31d6cfe0d16ae931b73c59d7e0c089c0'  # NTLM hash of empty string

    with open(secretsdump_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) < 4:
                continue
            username = parts[0]
            ntlm_hash = parts[3].lower()
            if ntlm_hash and ntlm_hash != EMPTY_NT:
                hash_to_users.setdefault(ntlm_hash, []).append(username)

    hash_file = os.path.join(tempfile.gettempdir(), 'hashgauntlet_ntlm.hash')
    with open(hash_file, 'w', encoding='utf-8') as f:
        for h in hash_to_users:
            f.write(h + '\n')

    _temp_files.append(hash_file)
    return hash_file, hash_to_users


def record_crack_timestamps(newly_cracked):
    """Record the current time for each newly cracked hash."""
    global _crack_timestamps
    now = time.time()
    for h in newly_cracked:
        if h not in _crack_timestamps:
            _crack_timestamps[h] = now


def classify_severity(elapsed_seconds):
    """
    Classify a cracked credential by time-to-crack.

    Critical - cracked in under 1 minute
    High     - cracked within 1 hour
    Medium   - cracked beyond 1 hour (or no timestamp available)
    """
    if elapsed_seconds < 60:
        return 'Critical'
    elif elapsed_seconds < 3600:
        return 'High'
    return 'Medium'


def _fmt_ttc(secs):
    """Human-readable time-to-crack."""
    if secs is None:
        return 'unknown'
    if secs < 60:
        return f"{secs:.1f}s"
    if secs < 3600:
        return f"{secs/60:.1f}m"
    return f"{secs/3600:.2f}h"


def compute_audit_analytics(total_cracked, crack_timestamps, hash_to_user, session_start):
    """
    Derive defensive analytics from the cracked set: crack rate, severity
    spread, password length/composition stats, and cross-account reuse.
    """
    from collections import Counter

    def users_for(h):
        raw = hash_to_user.get(h)
        if raw is None:
            return None
        return raw if isinstance(raw, list) else [raw]

    passwords = list(total_cracked.values())  # unique per NTLM hash
    lengths = [len(p) for p in passwords] or [0]
    length_dist = Counter(len(p) for p in passwords)
    composition = {
        'with_digit': sum(1 for p in passwords if any(c.isdigit() for c in p)),
        'with_upper': sum(1 for p in passwords if any(c.isupper() for c in p)),
        'with_lower': sum(1 for p in passwords if any(c.islower() for c in p)),
        'with_special': sum(1 for p in passwords if any(not c.isalnum() for c in p)),
    }

    sev = {'Critical': 0, 'High': 0, 'Medium': 0}
    reuse = []
    top = []
    accounts_affected = 0
    for h, pw in total_cracked.items():
        us = users_for(h)
        n = len(us) if us else 1
        accounts_affected += n
        if h in crack_timestamps:
            s = classify_severity(crack_timestamps[h] - session_start)
        else:
            s = 'Medium'
        sev[s] += n
        top.append((pw, n))
        if us and len(us) > 1:
            reuse.append({'password': pw, 'accounts': len(us), 'usernames': sorted(us)})

    reuse.sort(key=lambda r: r['accounts'], reverse=True)
    top.sort(key=lambda t: t[1], reverse=True)

    scope_hashes = len(hash_to_user) if hash_to_user else None
    scope_accounts = sum(len(v) for v in hash_to_user.values()) if hash_to_user else None

    return {
        'unique_hashes_cracked': len(total_cracked),
        'accounts_affected': accounts_affected,
        'hashes_in_scope': scope_hashes,
        'accounts_in_scope': scope_accounts,
        'hash_crack_rate': round(len(total_cracked) / scope_hashes, 4) if scope_hashes else None,
        'account_crack_rate': round(accounts_affected / scope_accounts, 4) if scope_accounts else None,
        'severity': {'critical': sev['Critical'], 'high': sev['High'], 'medium': sev['Medium']},
        'password_length': {
            'min': min(lengths), 'max': max(lengths),
            'avg': round(sum(lengths) / len(lengths), 1),
            'distribution': dict(sorted(length_dist.items())),
        },
        'composition': composition,
        'reuse': reuse,
        'top_passwords': [{'password': p, 'accounts': c} for p, c in top[:10]],
    }


def _write_txt_report(path, meta, entries, analytics):
    critical, high, medium = entries
    a = analytics
    with open(path, 'w', encoding='utf-8') as f:
        f.write("HashGauntlet - AD Credential Audit Report\n")
        if meta.get('organization'):
            f.write(f"Organization: {meta['organization']}\n")
        f.write(f"Generated:    {meta['generated']}\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"CRITICAL  ({len(critical)} accounts - cracked in <1 minute)\n")
        f.write("-" * 40 + "\n")
        for e in critical:
            f.write(f"  {e['username']:<30}  {e['password']}  [{_fmt_ttc(e['elapsed_seconds'])}]\n")

        f.write(f"\nHIGH      ({len(high)} accounts - cracked within 1 hour)\n")
        f.write("-" * 40 + "\n")
        for e in high:
            f.write(f"  {e['username']:<30}  {e['password']}  [{_fmt_ttc(e['elapsed_seconds'])}]\n")

        f.write(f"\nMEDIUM    ({len(medium)} accounts - cracked in >1 hour or untiered)\n")
        f.write("-" * 40 + "\n")
        for e in medium:
            f.write(f"  {e['username']:<30}  {e['password']}  [{_fmt_ttc(e['elapsed_seconds'])}]\n")

        f.write("\n" + "=" * 60 + "\n")
        f.write("ANALYTICS\n")
        if a['hashes_in_scope']:
            f.write(f"  Hashes cracked     : {a['unique_hashes_cracked']} / {a['hashes_in_scope']} "
                    f"({a['hash_crack_rate'] * 100:.1f}%)\n")
        else:
            f.write(f"  Hashes cracked     : {a['unique_hashes_cracked']}\n")
        if a['accounts_in_scope']:
            f.write(f"  Accounts affected  : {a['accounts_affected']} / {a['accounts_in_scope']} "
                    f"({a['account_crack_rate'] * 100:.1f}%)\n")
        else:
            f.write(f"  Accounts affected  : {a['accounts_affected']}\n")
        sv = a['severity']
        f.write(f"  Severity (accounts): Critical {sv['critical']} | High {sv['high']} | Medium {sv['medium']}\n")
        pl = a['password_length']
        f.write(f"  Password length    : min {pl['min']}, avg {pl['avg']}, max {pl['max']}\n")
        c = a['composition']
        f.write(f"  Composition        : digit {c['with_digit']}, upper {c['with_upper']}, "
                f"lower {c['with_lower']}, special {c['with_special']} (of {a['unique_hashes_cracked']} passwords)\n")
        if a['reuse']:
            shared_accounts = sum(r['accounts'] for r in a['reuse'])
            f.write(f"  Password reuse     : {len(a['reuse'])} passwords shared across {shared_accounts} accounts\n")
            for r in a['reuse'][:10]:
                f.write(f"     {r['password']:<24} x {r['accounts']} accounts\n")

        f.write("\n" + "=" * 60 + "\n")
        f.write("SUMMARY\n")
        f.write(f"  Unique hashes cracked : {a['unique_hashes_cracked']}\n")
        f.write(f"  Total accounts flagged: {a['accounts_affected']}\n")
        f.write(f"  Critical      : {sv['critical']}\n")
        f.write(f"  High          : {sv['high']}\n")
        f.write(f"  Medium        : {sv['medium']}\n")
        f.write("  Remediation   : Critical within 24h, High within 72h of report delivery\n")


def _write_json_report(path, meta, entries, analytics):
    critical, high, medium = entries
    findings = []
    for e in (critical + high + medium):
        findings.append({
            'username': e['username'],
            'severity': e['severity'],
            'password': e['password'],
            'ntlm_hash': e['hash'],
            'time_to_crack_seconds': e['elapsed_seconds'],
            'time_to_crack': _fmt_ttc(e['elapsed_seconds']),
        })
    doc = {
        'tool': 'HashGauntlet',
        'version': '3.0.0',
        'organization': meta.get('organization'),
        'generated': meta['generated'],
        'summary': analytics,
        'findings': findings,
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write('\n')


def _write_csv_report(path, entries, hash_to_user):
    import csv
    critical, high, medium = entries

    def shared_count(h):
        raw = hash_to_user.get(h)
        if raw is None:
            return 1
        return len(raw) if isinstance(raw, list) else 1

    with open(path, 'w', encoding='utf-8', newline='') as f:
        w = csv.writer(f)
        w.writerow(['username', 'severity', 'time_to_crack_seconds',
                    'time_to_crack', 'password', 'ntlm_hash', 'shared_accounts'])
        for e in (critical + high + medium):
            secs = e['elapsed_seconds']
            w.writerow([
                e['username'], e['severity'],
                f"{secs:.1f}" if secs is not None else '',
                _fmt_ttc(secs), e['password'], e['hash'],
                shared_count(e['hash']),
            ])


def generate_audit_report(total_cracked, crack_timestamps, hash_to_user,
                          report_path, org_name=None, session_start=None,
                          report_format='txt'):
    """
    Build the categorized findings report in one or more formats.

    report_format: 'txt' (default), 'json', 'csv', or 'all'. For a single
    format the file is written to report_path as given; 'all' writes sibling
    .txt/.json/.csv files next to report_path. Returns the list of paths written.
    """
    if session_start is None:
        session_start = min(crack_timestamps.values()) if crack_timestamps else time.time()

    critical, high, medium = [], [], []
    for h, plaintext in total_cracked.items():
        raw = hash_to_user.get(h)
        if raw is None:
            usernames = [h[:16] + '...' if len(h) > 16 else h]
        elif isinstance(raw, list):
            usernames = raw
        else:
            usernames = [raw]

        if h in crack_timestamps:
            elapsed = crack_timestamps[h] - session_start
            severity = classify_severity(elapsed)
        else:
            elapsed = None
            severity = 'Medium'

        for username in usernames:
            entry = {'username': username, 'hash': h, 'password': plaintext,
                     'elapsed_seconds': elapsed, 'severity': severity}
            if severity == 'Critical':
                critical.append(entry)
            elif severity == 'High':
                high.append(entry)
            else:
                medium.append(entry)

    entries = (critical, high, medium)
    analytics = compute_audit_analytics(total_cracked, crack_timestamps, hash_to_user, session_start)
    meta = {'organization': org_name,
            'generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

    def sibling(base, ext):
        if base.lower().endswith(('.txt', '.json', '.csv')):
            return os.path.splitext(base)[0] + '.' + ext
        return base + '.' + ext

    if report_format == 'all':
        outputs = [(sibling(report_path, 'txt'), 'txt'),
                   (sibling(report_path, 'json'), 'json'),
                   (sibling(report_path, 'csv'), 'csv')]
    else:
        outputs = [(report_path, report_format)]

    written = []
    for path, fmt in outputs:
        try:
            if fmt == 'json':
                _write_json_report(path, meta, entries, analytics)
            elif fmt == 'csv':
                _write_csv_report(path, entries, hash_to_user)
            else:
                _write_txt_report(path, meta, entries, analytics)
            written.append(path)
        except IOError as e:
            print(f"{CYAN}[!] Warning:{RESET} Could not write {fmt} report: {e}")
    return written


def encrypt_file_aes256(filepath):
    """
    Encrypt a file with AES-256-GCM, prompting for a passphrase.
    Writes <filepath>.enc and returns that path, or None on failure.
    The key is derived from the passphrase via SHA-256 (32 bytes = AES-256).
    """
    if not CRYPTO_AVAILABLE:
        print(f"{CYAN}[!] Warning:{RESET} 'cryptography' package not installed - log not encrypted.")
        print(f"    Install with: pip install cryptography")
        return None

    try:
        passphrase = getpass.getpass(f"\n{CYAN}[?]{RESET} Enter passphrase for AES-256 log encryption: ")
        if not passphrase:
            print(f"{CYAN}[!] No passphrase entered - log encryption skipped.{RESET}")
            return None

        key = hashlib.sha256(passphrase.encode('utf-8')).digest()  # 32 bytes → AES-256
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM

        with open(filepath, 'rb') as f:
            plaintext = f.read()

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        enc_path = filepath + '.enc'
        with open(enc_path, 'wb') as f:
            f.write(nonce + ciphertext)

        print(f"{CYAN}[+] Log encrypted with AES-256-GCM → {enc_path}{RESET}")
        return enc_path

    except Exception as e:
        print(f"{CYAN}[!] Warning:{RESET} Encryption failed: {e}")
        return None


def main():
    global _quiet_mode, _no_leet

    args = parse_args()

    # Set quiet mode flag
    _quiet_mode = args.quiet

    # Set no-leet mode flag
    _no_leet = args.no_leet

    # Apply AD-mode preset: auto-set NTLM hash mode
    if args.ad_mode:
        if args.hash_mode is None:
            args.hash_mode = 1000  # NTLM

    # Handle secretsdump input: parse it and generate a clean NTLM hash file
    global _hash_to_user, _session_start_time
    if args.secretsdump:
        if not os.path.exists(args.secretsdump):
            print(f"{CYAN}[!] Error:{RESET} Secretsdump file not found: {args.secretsdump}")
            sys.exit(1)
        sd_hash_file, _hash_to_user = parse_secretsdump(args.secretsdump)
        if not _hash_to_user:
            print(f"{CYAN}[!] Error:{RESET} No NTLM hashes found in secretsdump file")
            sys.exit(1)
        args.hash_file = sd_hash_file
        if args.hash_mode is None:
            args.hash_mode = 1000  # NTLM is the only mode secretsdump hashes make sense with
        total_accounts = sum(len(v) for v in _hash_to_user.values())
        print(f"{CYAN}[+] Parsed {len(_hash_to_user)} unique NTLM hashes ({total_accounts} accounts) from secretsdump output{RESET}")

    # Validate required inputs
    if not args.hash_file:
        print(f"{CYAN}[!] Error:{RESET} --hash-file (-f) or --secretsdump is required")
        sys.exit(1)
    if args.hash_mode is None:
        print(f"{CYAN}[!] Error:{RESET} --hash-mode (-m) is required (or use --ad-mode)")
        sys.exit(1)
    if not args.base_wordlist:
        print(f"{CYAN}[!] Error:{RESET} --base-wordlist (-b) is required")
        sys.exit(1)

    # Validate conflicting options
    if args.no_leet and args.selective_leet is not None:
        print(f"{CYAN}[!] Error:{RESET} --no-leet and --selective-leet cannot be used together")
        sys.exit(1)

    # Validate that files/directories exist
    if not os.path.exists(args.hash_file):
        print(f"{CYAN}[!] Error:{RESET} Hash file not found: {args.hash_file}")
        sys.exit(1)

    if not os.path.exists(args.base_wordlist):
        print(f"{CYAN}[!] Error:{RESET} Base wordlist not found: {args.base_wordlist}")
        sys.exit(1)

    # Check if hashcat binary exists
    hashcat_path = shutil.which(args.hashcat_bin)
    if not hashcat_path:
        print(f"{CYAN}[!] Error:{RESET} Hashcat binary not found: {args.hashcat_bin}")
        print(f"    Please install hashcat or specify the path with --hashcat-bin")
        sys.exit(1)

    # Create output directory
    output_dir = os.path.dirname(args.log_file) or '.'
    os.makedirs(output_dir, exist_ok=True)

    _session_start_time = time.time()

    # Initialize
    log_separator(args.log_file)
    log_message(f"{CYAN}[+] HashGauntlet - AD Credential Auditing Tool{RESET}", args.log_file)
    log_separator(args.log_file)
    if args.secretsdump:
        log_message(f"Secretsdump input: {args.secretsdump}", args.log_file)
        log_message(f"NTLM hashes extracted: {len(_hash_to_user)} unique ({sum(len(v) for v in _hash_to_user.values())} accounts)", args.log_file)
    if getattr(args, 'org_name', None):
        log_message(f"Organization: {args.org_name}", args.log_file)
    if getattr(args, 'org_location', None):
        log_message(f"Location(s): {', '.join(args.org_location)}", args.log_file)
    log_message(f"Hash file: {args.hash_file}", args.log_file)
    log_message(f"Hash mode: {args.hash_mode}", args.log_file)
    log_message(f"Base wordlist: {args.base_wordlist}", args.log_file)
    log_message(f"Max time per attempt: {args.max_time} hours", args.log_file)
    log_message(f"Max wordlist size: {args.max_size} MB", args.log_file)
    log_separator(args.log_file)

    # Build wordlists if preprocessing is enabled
    wordlist_dir = 'wordlists'
    if args.preprocess or args.case or args.separators or args.selective_leet is not None:
        if not _quiet_mode:
                print()
        log_separator(args.log_file)
        log_message(f"{CYAN}[+] Forging Candidate Wordlists{RESET}", args.log_file)
        log_separator(args.log_file)

        # Parse toggle depths from string to set of integers
        # '0' or empty = no toggles, '1' = 1-char only, '1,2,3' = all three
        toggle_depths = set()
        if args.toggles is not None and args.toggles != '0':
            try:
                toggle_depths = set(int(x.strip()) for x in args.toggles.split(','))
                # Validate values are 1, 2, or 3
                if not toggle_depths.issubset({1, 2, 3}):
                    print(f"{CYAN}[!] Error:{RESET} Toggle depths must be 0, 1, 2, or 3")
                    sys.exit(1)
            except ValueError:
                print(f"{CYAN}[!] Error:{RESET} Invalid toggle format. Use '0', '1', '2', '3', or '1,2,3'")
                sys.exit(1)

        # Prepend org-specific seed words to the base wordlist before preprocessing
        effective_wordlist = args.base_wordlist
        org_seeds = []
        if getattr(args, 'org_name', None):
            org_seeds.append(args.org_name)
        if getattr(args, 'org_location', None):
            org_seeds.extend(args.org_location)
        if org_seeds:
            seed_path = os.path.join(tempfile.gettempdir(), 'hashgauntlet_org_seeds.txt')
            with open(seed_path, 'w', encoding='utf-8') as sf:
                with open(args.base_wordlist, 'r', encoding='utf-8', errors='ignore') as bf:
                    sf.write('\n'.join(org_seeds) + '\n')
                    sf.write(bf.read())
            effective_wordlist = seed_path
            _temp_files.append(seed_path)
            log_message(f"Injected {len(org_seeds)} org-specific seed word(s) into wordlist", args.log_file)

        build_wordlists_ncl_style(effective_wordlist, wordlist_dir, no_leet=args.no_leet, toggle_depths=toggle_depths)

    # Create intermediate wordlists for two-sided attacks with disk space safety checks
    intermediate_wordlists = None

    # Get optimal temp directory (needed for attacks even if no preprocessing)
    temp_dir = get_optimal_temp_dir()

    if args.preprocess or args.case or args.separators or args.selective_leet is not None:
        if not _quiet_mode:
                print()
        log_separator(args.log_file)
        log_message(f"{CYAN}[+] Staging Attack Wordlists{RESET}", args.log_file)
        log_separator(args.log_file)

        log_message(f"Using temp directory: {temp_dir}", args.log_file)

        # Determine base and leet wordlist paths
        base_name = os.path.splitext(os.path.basename(args.base_wordlist))[0]
        all_wordlist = os.path.join(wordlist_dir, f"all_{base_name}.txt")
        leet_wordlist = os.path.join(wordlist_dir, f"leet_{base_name}.txt")

        # Check available disk space and estimate requirements
        available_space = get_available_disk_space(temp_dir)

        # Estimate size for pre-split files instead of intermediates
        # Each base wordlist gets split into ~12 files (6 within + 6 over)
        # Rough estimate: split files total size ≈ 2x original size
        all_wordlist_size = os.path.getsize(all_wordlist) if os.path.exists(all_wordlist) else 0
        leet_wordlist_size = os.path.getsize(leet_wordlist) if (not args.no_leet and os.path.exists(leet_wordlist)) else 0
        estimated_presplit_size = (all_wordlist_size + leet_wordlist_size) * 2

        # Add 20% buffer for safety
        required_space = estimated_presplit_size * 1.2

        # Display disk space information
        log_message(f"Available disk space: {available_space / (1024**3):.2f} GB", args.log_file)

        # Two-tier fallback logic (only pre-split if -O flag is used)
        if available_space < 1024**3:  # Less than 1GB available
            log_message(f"{CYAN}[!] Unable to estimate disk space{RESET}", args.log_file)
            log_message(f"Using fallback method...", args.log_file)
            intermediate_wordlists = None
        elif args.optimize_kernels and available_space >= required_space:
            # Tier 1: Enough space for pre-split wordlists
            log_message(f"Pre-splitting wordlists by length...")

            # Count wordlists to pre-split
            num_base_wordlists = 1 if os.path.exists(all_wordlist) else 0
            num_leet_wordlists = 1 if (not args.no_leet and os.path.exists(leet_wordlist)) else 0

            # Each wordlist gets split into 6 iterations × 2 files = 12 files per wordlist
            total_files = (num_base_wordlists + num_leet_wordlists) * 12
            current = 0

            # Pre-split all_wordlist
            if os.path.exists(all_wordlist):
                presplit_wordlists_by_length(all_wordlist, args.hash_mode, temp_dir, current, total_files)
                current += 12

            # Pre-split leet_wordlist if it exists and --no-leet not specified
            if not args.no_leet and os.path.exists(leet_wordlist):
                presplit_wordlists_by_length(leet_wordlist, args.hash_mode, temp_dir, current, total_files)
                current += 12

            if not _quiet_mode:
                print()

            # Mark success - we'll use these pre-split files for upstream splitting
            intermediate_wordlists = {'presplit_cache': True}  # Dummy dict to indicate success
            log_message(f"Candidate lists prepared", args.log_file)
        else:
            # Tier 2: Not enough space for pre-split or -O not requested - use on-the-fly generation
            if not _quiet_mode:
                    print()
            log_message(f"{CYAN}[!] Insufficient disk space or -O not requested{RESET}", args.log_file)
            log_message(f"Using fallback method...", args.log_file)
            intermediate_wordlists = None

    # Get wordlists and rules
    wordlists = get_wordlists_sorted(wordlist_dir)
    rule_files = get_rule_files(args.rules_dir)
    # Filter out void rules if specified
    if args.void_rules:
        rule_files = [r for r in rule_files if not any(void in os.path.basename(r) for void in args.void_rules)]

    if not _quiet_mode:
            print()
    log_separator(args.log_file)
    log_message(f"{CYAN}[+] Loading Wordlists and Rules{RESET}") 
    log_separator(args.log_file)

    log_message(f"Found {len(wordlists)} wordlists", args.log_file)
    log_message(f"Found {len(rule_files)} rule files", args.log_file)

    # Check if wordlist directory is empty
    if len(wordlists) == 0:
        if not _quiet_mode:
            print()
        log_message(f"{CYAN}[!] Warning:{RESET} No wordlists found in {wordlist_dir}", args.log_file)
        log_message("Please add wordlist files to the directory and try again.", args.log_file)
        sys.exit(1)
    
    # Generate mask variations based on coverage level
    if args.coverage == 1:
        log_message("Using optimized attack strategy", args.log_file)
        pure_masks = generate_coverage1_attacks()
        log_message(f"Coverage Level 1: {len(pure_masks)} attacks", args.log_file)
        log_message(f"Estimated coverage: ~90%", args.log_file)
    elif args.coverage == 2:
        log_message("Using extended attack strategy", args.log_file)
        pure_masks = generate_coverage2_attacks()
        log_message(f"Coverage Level 2: {len(pure_masks)} attacks", args.log_file)
        log_message(f"Estimated coverage: ~95%", args.log_file)
    elif args.coverage == 3:
        log_message("Using comprehensive attack strategy", args.log_file)
        pure_masks = generate_coverage3_attacks()
        log_message(f"Coverage Level 3: {len(pure_masks)} attacks", args.log_file)
        log_message(f"Estimated coverage: ~98%", args.log_file)
    else:
        # Default to coverage 1
        log_message("Using optimized attack strategy", args.log_file)
        pure_masks = generate_coverage1_attacks()
        log_message(f"Coverage 1: {len(pure_masks)} attacks", args.log_file)
        log_message(f"Estimated coverage: ~90% | Expected time: 4-6 hours", args.log_file)

    # Start keyboard monitoring for interactive controls
    start_keyboard_monitor()

    # Track progress
    total_cracked = {}
    total_attempts = 0
    total_skipped = 0

    # Get total hash count for progress display
    total_hashes = count_hash_lines(args.hash_file)

    # Process each wordlist
    for wordlist_path, wordlist_size in wordlists:
        wordlist_name = os.path.basename(wordlist_path)

        # Skip leet wordlists if --no-leet is enabled
        if args.no_leet and wordlist_name.startswith('leet_'):
            continue

        if not _quiet_mode:
            print()  # Blank line for readability
        log_separator(args.log_file)
        log_message(f"{CYAN}[+] Cracking: {wordlist_name} ({format_size(wordlist_size)}){RESET}", args.log_file)
        log_separator(args.log_file)

        # Phase 1: Base wordlist attacks
        if not _quiet_mode:
                print()
        log_message("--- Dictionary Attack ---\n", args.log_file)

        # Straight dictionary (always runs)
        log_message("Attempting: Straight dictionary", args.log_file)

        # Show interactive prompt before first attack
        show_interactive_prompt()

        if args.force:
            # Force single pass with -O
            result = run_hashcat_attack_single(args.hashcat_bin, args.hash_file, args.hash_mode,
                                       wordlist_path, output_dir, timeout_hours=args.max_time,
                                       workload=args.workload, use_optimized=True,
                                       slow_candidates=args.slow_candidates)
        else:
            result = run_hashcat_attack(args.hashcat_bin, args.hash_file, args.hash_mode,
                                       wordlist_path, output_dir, timeout_hours=args.max_time,
                                       workload=args.workload, optimize_kernels=args.optimize_kernels,
                                       slow_candidates=args.slow_candidates)

        # Reset attack-specific flags after each attack
        _session_control.reset_attack_flags()

        # Get newly cracked hashes (not in total_cracked yet)
        newly_cracked = {h: p for h, p in result['cracked'].items() if h not in total_cracked}
        new_cracks = len(newly_cracked)
        record_crack_timestamps(newly_cracked)
        total_cracked.update(result['cracked'])
        log_message(f"Completed in {result['elapsed_hours']:.2f}h | {format_crack_count(new_cracks, len(total_cracked), newly_cracked, total_hashes)}", args.log_file)

        # Still log to file separately
        for hash_val, plaintext in newly_cracked.items():
            log_cracked(hash_val, plaintext, args.log_file)

        total_attempts += 1

        # Check if all hashes have been cracked
        if len(total_cracked) == total_hashes:
            break

        # Check if session should stop after this attack
        if _session_control.should_kill():
            cleanup_status_bar()
            if not _quiet_mode:
                    print()
            log_message(f"{CYAN}[!] Cleaning up temporary files...{RESET}")
            log_message(f"{CYAN}[!] HashGauntlet session terminated{RESET}", args.log_file)
            break

        if _session_control.should_finish():
            cleanup_status_bar()
            if not _quiet_mode:
                print()
            log_message(f"{CYAN}[!] Cleaning up temporary files...{RESET}")
            log_message(f"{CYAN}[!] HashGauntlet session terminated{RESET}", args.log_file)
            break

        # Single rules (skip if --disable-rules)
        if not args.disable_rules:
            for rule_file in rule_files:
                rule_name = os.path.basename(rule_file)
                if not _quiet_mode:
                    print()
                log_message(f"Attempting: {wordlist_name} + {rule_name}", args.log_file)

                # Show interactive prompt before first attack
                show_interactive_prompt()

                if args.force:
                    # Force single pass with -O
                    result = run_hashcat_attack_single(args.hashcat_bin, args.hash_file, args.hash_mode,
                                               wordlist_path, output_dir, rules=[rule_file],
                                               timeout_hours=args.max_time, workload=args.workload,
                                               use_optimized=True,
                                               slow_candidates=args.slow_candidates)
                else:
                    result = run_hashcat_attack(args.hashcat_bin, args.hash_file, args.hash_mode,
                                               wordlist_path, output_dir, rules=[rule_file],
                                               timeout_hours=args.max_time, workload=args.workload,
                                               optimize_kernels=args.optimize_kernels,
                                               slow_candidates=args.slow_candidates)

                # Reset attack-specific flags after each attack
                _session_control.reset_attack_flags()

                # Get newly cracked hashes (not in total_cracked yet)
                newly_cracked = {h: p for h, p in result['cracked'].items() if h not in total_cracked}
                new_cracks = len(newly_cracked)
                record_crack_timestamps(newly_cracked)
                total_cracked.update(result['cracked'])
                log_message(f"Completed in {result['elapsed_hours']:.2f}h | {format_crack_count(new_cracks, len(total_cracked), newly_cracked, total_hashes)}", args.log_file)

                # Still log to file separately
                for hash_val, plaintext in newly_cracked.items():
                    log_cracked(hash_val, plaintext, args.log_file)

                total_attempts += 1

                # Check if all hashes have been cracked
                if len(total_cracked) == total_hashes:
                    break

                # Check if session should stop after this attack
                if _session_control.should_kill():
                    cleanup_status_bar()
                    if not _quiet_mode:
                        print()
                    log_message(f"{CYAN}[!] Cleaning up temporary files...{RESET}")
                    log_message(f"{CYAN}[!] HashGauntlet session terminated{RESET}", args.log_file)
                    break

                if _session_control.should_finish():
                    cleanup_status_bar()
                    if not _quiet_mode:
                        print()
                    log_message(f"{CYAN}[!] Cleaning up temporary files...{RESET}")
                    log_message(f"{CYAN}[!] HashGauntlet session terminated{RESET}", args.log_file)
                    break

            # Check if we should stop after single rules
            if _session_control.should_kill() or _session_control.should_finish():
                break

        # 2-rule combinations (skip if --disable-rules or --skip-combos)
        if not args.disable_rules and not args.skip_combos:
            if not _quiet_mode:
                print()
            log_message("--- Two-Rule Combinations ---", args.log_file)
            for i, rule1 in enumerate(rule_files[:5]):
                for rule2 in rule_files[i+1:6]:
                    rule1_name = os.path.basename(rule1)
                    rule2_name = os.path.basename(rule2)

                    # Skip the nightmare combo: dive.rule + d3adhob0.rule (1.38 billion rules = 200GB+ RAM)
                    forbidden_combos = [
                        ('dive.rule', 'd3adhob0.rule'),
                        ('d3adhob0.rule', 'dive.rule')
                    ]
                    if (rule1_name, rule2_name) in forbidden_combos:
                        if not _quiet_mode:
                            print()
                        log_message(f"SKIPPING COMBO: {rule1_name} + {rule2_name} (Exceeds RAM)", args.log_file)
                        total_skipped += 1
                        continue
                    if not _quiet_mode:
                        print()
                    log_message(f"Attempting: {wordlist_name} + {rule1_name} + {rule2_name}", args.log_file)

                    # Show interactive prompt before first attack
                    show_interactive_prompt()

                    result = run_hashcat_attack(args.hashcat_bin, args.hash_file, args.hash_mode,
                                               wordlist_path, output_dir, rules=[rule1, rule2],
                                               timeout_hours=args.max_time, workload=args.workload,
                                               optimize_kernels=args.optimize_kernels,
                                               slow_candidates=args.slow_candidates)

                    # Reset attack-specific flags after each attack
                    _session_control.reset_attack_flags()

                    # Get newly cracked hashes (not in total_cracked yet)
                    newly_cracked = {h: p for h, p in result['cracked'].items() if h not in total_cracked}
                    new_cracks = len(newly_cracked)
                    record_crack_timestamps(newly_cracked)
                    total_cracked.update(result['cracked'])
                    log_message(f"Completed in {result['elapsed_hours']:.2f}h | {format_crack_count(new_cracks, len(total_cracked), newly_cracked, total_hashes)}", args.log_file)

                    # Still log to file separately
                    for hash_val, plaintext in newly_cracked.items():
                        log_cracked(hash_val, plaintext, args.log_file)

                    total_attempts += 1

                    # Check if all hashes have been cracked
                    if len(total_cracked) == total_hashes:
                        break

                    # Check if session should stop after this attack
                    if _session_control.should_kill():
                        cleanup_status_bar()
                        if not _quiet_mode:
                            print()
                        log_message(f"{CYAN}[!] Cleaning up temporary files...{RESET}")
                        log_message(f"{CYAN}[!] HashGauntlet session terminated{RESET}", args.log_file)
                        break

                    if _session_control.should_finish():
                        cleanup_status_bar()
                        if not _quiet_mode:
                            print()
                        log_message(f"{CYAN}[!] Cleaning up temporary files...{RESET}")
                        log_message(f"{CYAN}[!] HashGauntlet session terminated{RESET}", args.log_file)
                        break

                # Check if we should break out of the outer loop
                if _session_control.should_kill() or _session_control.should_finish():
                    break

            # Check if we should stop after 2-rule combinations
            if _session_control.should_kill() or _session_control.should_finish():
                break

        # Phase 2: Optimized mask attacks
        if len(pure_masks) > 0:
            attempts, skipped = process_wordlist_with_variations(
                args, wordlist_path, wordlist_name, pure_masks, rule_files,
                output_dir, total_cracked, "Mask Attacks", intermediate_wordlists, temp_dir
            )
            total_attempts += attempts
            total_skipped += skipped

        # Check if we should stop after mask attacks
        if _session_control.should_kill() or _session_control.should_finish():
            cleanup_status_bar()
            if not _quiet_mode:
                print()
            log_message(f"{CYAN}[!] Cleaning up temporary files...{RESET}")
            log_message(f"{CYAN}[!] HashGauntlet session terminated{RESET}", args.log_file)
            break
        if not _quiet_mode:
            print()
        log_message(f"--- Completed {wordlist_name} ---", args.log_file)
        log_message(f"Total cracked: {len(total_cracked)}", args.log_file)
    
    # Final summary
    cleanup_status_bar()
    if not _quiet_mode:
            print()
    log_separator(args.log_file)
    log_message(f"{CYAN}FINAL SUMMARY{RESET}", args.log_file)
    log_separator(args.log_file)
    log_message(f"Total attempts: {total_attempts}", args.log_file)
    log_message(f"Total skipped: {total_skipped}", args.log_file)
    log_message(f"{CYAN}Total cracked: {len(total_cracked)}/{total_hashes}{RESET}", args.log_file)
    log_message(f"Results saved to: {args.log_file}", args.log_file)
    log_separator(args.log_file)

    # Generate categorized findings report
    if getattr(args, 'report', None):
        written_reports = generate_audit_report(
            total_cracked, _crack_timestamps, _hash_to_user,
            args.report, getattr(args, 'org_name', None), _session_start_time,
            report_format=getattr(args, 'report_format', 'txt')
        )
        for _rp in (written_reports or []):
            log_message(f"Audit report saved to: {_rp}", args.log_file)

    # Encrypt audit log with AES-256-GCM
    if getattr(args, 'encrypt_log', False):
        enc_path = encrypt_file_aes256(args.log_file)
        if enc_path:
            log_message(f"Encrypted log saved to: {enc_path}")


if __name__ == '__main__':
    main()
