import re
from src.honeypot import detect_attack

result = detect_attack('hello world')
print('hello world detects:', result)

patterns = [
    (r';\s*cat\s', 'cat'),
    (r';\s*ls\s', 'ls'),
    (r';\s*wget\s', 'wget'),
    (r';\s*curl\s', 'curl'),
    (r'\|\s*bash', 'bash pipe'),
    (r'\$\(.*\)', 'subshell'),
]
for p, name in patterns:
    if re.search(p, 'hello world', re.IGNORECASE):
        print('Matched:', name)
