import os
import time
import json
import hashlib
import getpass
from pathlib import Path

class AuthSessionManager:
    """Manages CLI Authentication and Session timeouts."""
    
    SESSION_TIMEOUT = 3600 # 1 hour
    
    def __init__(self, root_dir: str = "."):
        self.creds_file = Path(root_dir) / ".aegisx_creds.json"
        self.session_file = Path(root_dir) / ".aegisx_session"

    def _hash_password(self, password: str, salt: str = "aegisx-salt") -> str:
        return hashlib.sha256(f"{salt}{password}".encode('utf-8')).hexdigest()

    def _setup_initial_creds(self):
        """One-time setup to create a custom username and password."""
        print("\n=== AEGIS-X Initial Setup ===")
        print("No credentials found. Please set up your administrator account.")
        while True:
            username = input("Enter new username: ").strip()
            if not username:
                print("Username cannot be empty.")
                continue
            
            password = getpass.getpass("Enter new password: ")
            if not password:
                print("Password cannot be empty.")
                continue
                
            confirm_password = getpass.getpass("Confirm password: ")
            
            if password != confirm_password:
                print("Passwords do not match. Please try again.\n")
                continue
                
            # Save credentials
            creds = {
                username: self._hash_password(password)
            }
            with open(self.creds_file, 'w') as f:
                json.dump(creds, f)
            os.chmod(self.creds_file, 0o600)
            print(f"[+] Account '{username}' created successfully.\n")
            
            # Auto-login after creation
            self._update_activity()
            return

    def _verify_credentials(self, username: str, password: str) -> bool:
        if not self.creds_file.exists():
            return False
            
        with open(self.creds_file, 'r') as f:
            creds = json.load(f)
            
        stored_hash = creds.get(username)
        if not stored_hash:
            return False
            
        return stored_hash == self._hash_password(password)

    def _get_last_activity(self) -> float:
        if not self.session_file.exists():
            return 0.0
        try:
            with open(self.session_file, 'r') as f:
                return float(f.read().strip())
        except ValueError:
            return 0.0

    def _update_activity(self):
        with open(self.session_file, 'w') as f:
            f.write(str(time.time()))
        os.chmod(self.session_file, 0o600)

    def check_session(self):
        """
        Validates the session. If expired (> 1 hour) or not logged in,
        prompts the user to login. Performs one-time setup if no creds exist.
        """
        # 1. Check for one-time setup
        if not self.creds_file.exists():
            self._setup_initial_creds()
            return
            
        # 2. Enforce session
        last_activity = self._get_last_activity()
        current_time = time.time()
        
        if last_activity == 0.0:
            print("[Governance] No active session. Please log in.")
            self._prompt_login()
        elif (current_time - last_activity) > self.SESSION_TIMEOUT:
            print("\n[Governance] Session expired (Inactive for > 1 hour). Please re-login.")
            self._prompt_login()
        else:
            # Session is valid, update the timestamp to extend it
            self._update_activity()

    def _prompt_login(self):
        max_attempts = 3
        for attempt in range(max_attempts):
            print("\n--- AEGIS-X Authentication ---")
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            
            if self._verify_credentials(username, password):
                print(f"[+] Login successful. Welcome, {username}.")
                self._update_activity()
                return
            else:
                print("[-] Invalid credentials.")
                
        print("\n[FATAL] Maximum authentication attempts reached.")
        exit(1)
