import hashlib
import requests
import re
from datetime import datetime

class SecurityService:
    
    @staticmethod
    def check_password_breach(password):
        """
        Checks HaveIBeenPwned API using k-Anonymity (SHA-1 prefix).
        """
        try:
            # 1. Hash the password (SHA-1)
            sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1_password[:5], sha1_password[5:]
            
            # FIX: Correct URL formatting
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount{prefix}"
            
            res = requests.get(url, timeout=2) 
            
            if res.status_code != 200:
                return 0

            # 2. Check if our suffix exists in the response
            hashes = (line.split(':') for line in res.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return int(count)
            return 0
            
        except Exception as e:
            print(f"⚠️ Breach Check Failed: {e}")
            return 0

    @staticmethod
    def detect_sql_injection(input_str):
        """Basic regex check for common SQL Injection patterns (for input cleansing)"""
        if not isinstance(input_str, str): return False
        sql_patterns = [
            r"(\%27)|(\')", 
            r"(\-\-)",      
            r"(\%23)",      
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))", 
            r"\w*((\%27)|(\'))(\s)*((\%6F)|o|(\%4F))((\%72)|r|(\%52))"
        ]
        for pattern in sql_patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                return True
        return False