# Password Strength Analyzer & Cracker

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://opensource.org/licenses/MIT)


A security tool that analyzes password strength and demonstrates cracking techniques for educational purposes.

## Features

- 🔍 Password strength analysis (length, complexity, entropy)
- ⚡ Hash cracking demo (dictionary & brute force)
- 🖥️ Dual interface (CLI + Web)
- 📊 Strength meter with recommendations

## Quick Start

### Install dependencies
```
pip install flask
```

### Run web interface
```
python password_tool.py
```

### Or use CLI
```
python password_tool.py --analyze "YourPassword123"
```

## Usage Examples

**Analyze password:**
```
python password_tool.py --analyze "MySecurePassw0rd!"
```

**Crack demo hash:**
```
python password_tool.py --crack --hash "5f4dcc3b5aa765d61d8327deb882cf99" --algorithm md5
```

**Web Interface:**
```
python password_tool.py
```
#### Visit http://localhost:5000

⚠️ **Ethical Use Only** - For educational purposes only. Never use on systems without permission.

