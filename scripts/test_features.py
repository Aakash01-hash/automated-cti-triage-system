import sys
import os

# Fix module path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from feature_engineering.feature_extractor import extract_features

text = """
Threat actor used phishing attack exploiting CVE-2022-30190.
Connected to malicious IP 192.168.1.5 and domain evil.com.
"""

features = extract_features(text)

print("Features:", features)