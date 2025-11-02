import sys
sys.path.append('.')
from src.core.system_scanner import SystemScanner

scanner = SystemScanner()
print(f'✅ CyberAudit v2.0 loaded successfully!')
print(f'📊 Total security modules: {len(scanner.checks)}')
print('🔍 Modules loaded:')
for i, (name, func) in enumerate(scanner.checks, 1):
    print(f'  {i:2d}. {name}')