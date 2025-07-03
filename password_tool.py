#!/usr/bin/env python3
import argparse
import hashlib
import math
import os
import sys
import time
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
        
    def load_common_passwords(self):
        try:
            with open('rockyou.txt', 'r', encoding='latin-1') as f:
                return [line.strip() for line in f]
        except FileNotFoundError:
            print("Warning: rockyou.txt not found. Using smaller built-in dictionary.")
            return [
                'password', '123456', 'qwerty', 'abc123', 'letmein',
                'monkey', 'password1', 'admin', 'welcome', 'sunshine'
            ]
    
    def calculate_entropy(self, password):
        """Calculate password entropy in bits"""
        char_sets = {
            'lower': 26, 'upper': 26, 'digits': 10,
            'special': 32, 'other': 1
        }
        
        pool = 0
        if any(c.islower() for c in password):
            pool += char_sets['lower']
        if any(c.isupper() for c in password):
            pool += char_sets['upper']
        if any(c.isdigit() for c in password):
            pool += char_sets['digits']
        if any(not c.isalnum() for c in password):
            pool += char_sets['special']
            
        if pool == 0:
            return 0
            
        length = len(password)
        entropy = length * math.log2(pool)
        return round(entropy, 2)
    
    def analyze_strength(self, password):
        analysis = {
            'length': len(password),
            'has_lower': any(c.islower() for c in password),
            'has_upper': any(c.isupper() for c in password),
            'has_digit': any(c.isdigit() for c in password),
            'has_special': any(not c.isalnum() for c in password),
            'is_common': password.lower() in [p.lower() for p in self.common_passwords],
            'entropy': self.calculate_entropy(password)
        }
        
        # Strength rating
        score = 0
        if analysis['length'] >= 8: score += 1
        if analysis['length'] >= 12: score += 1
        if analysis['has_lower']: score += 1
        if analysis['has_upper']: score += 1
        if analysis['has_digit']: score += 1
        if analysis['has_special']: score += 2
        if not analysis['is_common']: score += 2
        if analysis['entropy'] > 60: score += 1
        if analysis['entropy'] > 80: score += 1
        
        analysis['strength'] = min(max(score, 1), 10)
        return analysis
    
    def crack_password(self, target_hash, algorithm='sha256', mode='dictionary'):
        start_time = time.time()
        attempts = 0
        
        if mode == 'dictionary':
            for password in self.common_passwords:
                attempts += 1
                hashed = hashlib.new(algorithm, password.encode()).hexdigest()
                if hashed == target_hash:
                    return {
                        'found': True,
                        'password': password,
                        'attempts': attempts,
                        'time': round(time.time() - start_time, 2)
                    }
        
        elif mode == 'brute':
            chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
            max_length = 4  # For demo purposes - keep it short!
            
            from itertools import product
            for length in range(1, max_length + 1):
                for guess in product(chars, repeat=length):
                    attempts += 1
                    guess = ''.join(guess)
                    hashed = hashlib.new(algorithm, guess.encode()).hexdigest()
                    if hashed == target_hash:
                        return {
                            'found': True,
                            'password': guess,
                            'attempts': attempts,
                            'time': round(time.time() - start_time, 2)
                        }
        
        return {
            'found': False,
            'attempts': attempts,
            'time': round(time.time() - start_time, 2)
        }

# CLI Interface
def cli_interface():
    parser = argparse.ArgumentParser(description='Password Strength Analyzer & Cracker')
    parser.add_argument('--analyze', help='Analyze password strength')
    parser.add_argument('--crack', action='store_true', help='Run cracking demo')
    parser.add_argument('--mode', choices=['dictionary', 'brute'], default='dictionary', 
                       help='Cracking mode (dictionary/brute)')
    parser.add_argument('--hash', help='Hash to crack')
    parser.add_argument('--algorithm', default='sha256', 
                       choices=['md5', 'sha1', 'sha256', 'sha512'],
                       help='Hashing algorithm')
    
    args = parser.parse_args()
    analyzer = PasswordAnalyzer()
    
    if args.analyze:
        result = analyzer.analyze_strength(args.analyze)
        print("\nPassword Analysis:")
        print(f"Length: {result['length']}")
        print(f"Contains lowercase: {'Yes' if result['has_lower'] else 'No'}")
        print(f"Contains uppercase: {'Yes' if result['has_upper'] else 'No'}")
        print(f"Contains digits: {'Yes' if result['has_digit'] else 'No'}")
        print(f"Contains special chars: {'Yes' if result['has_special'] else 'No'}")
        print(f"Common password: {'Yes' if result['is_common'] else 'No'}")
        print(f"Entropy: {result['entropy']} bits")
        print(f"Strength: {result['strength']}/10")
        
        # Strength tips
        print("\nRecommendations:")
        if result['length'] < 8:
            print("- Use at least 8 characters")
        if not result['has_lower']:
            print("- Add lowercase letters")
        if not result['has_upper']:
            print("- Add uppercase letters")
        if not result['has_digit']:
            print("- Add numbers")
        if not result['has_special']:
            print("- Add special characters")
        if result['is_common']:
            print("- Avoid common dictionary words")
    
    elif args.crack:
        if not args.hash:
            print("Please provide a hash with --hash")
            return
            
        print(f"\nAttempting {args.mode} attack on {args.algorithm} hash...")
        result = analyzer.crack_password(args.hash, args.algorithm, args.mode)
        
        if result['found']:
            print(f"\nPassword cracked in {result['time']} seconds!")
            print(f"Password: {result['password']}")
            print(f"Attempts: {result['attempts']}")
        else:
            print("\nPassword not found in demo attack")
            print(f"Attempts: {result['attempts']}")
            print(f"Time: {result['time']} seconds")
        
        print("\nNote: This demo uses limited resources. Real cracking would:")
        print("- Use larger dictionaries")
        print("- Try more combinations")
        print("- Use GPU acceleration")

# Web Interface
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    password = request.form.get('password', '')
    analyzer = PasswordAnalyzer()
    result = analyzer.analyze_strength(password)
    return jsonify(result)

@app.route('/crack', methods=['POST'])
def crack():
    data = request.get_json()
    analyzer = PasswordAnalyzer()
    result = analyzer.crack_password(
        data['hash'],
        data.get('algorithm', 'sha256'),
        data.get('mode', 'dictionary')
    )
    return jsonify(result)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        cli_interface()
    else:
        print("Starting web server...")
        if not os.path.exists('templates'):
            os.makedirs('templates')
            with open('templates/index.html', 'w') as f:
                f.write('''<!DOCTYPE html>
<html>
<head>
    <title>Password Analyzer</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .result { margin-top: 20px; padding: 15px; border-radius: 5px; }
        .weak { background-color: #ffdddd; }
        .medium { background-color: #fff3cd; }
        .strong { background-color: #d4edda; }
        .meter { height: 20px; background: #eee; margin: 10px 0; }
        .meter-bar { height: 100%; background: #4CAF50; width: 0%; }
    </style>
</head>
<body>
    <h1>Password Strength Analyzer</h1>
    <input type="password" id="password" placeholder="Enter password to analyze">
    <button onclick="analyze()">Analyze</button>
    <div id="result" class="result" style="display:none;">
        <h3>Analysis Results</h3>
        <div class="meter">
            <div id="meter-bar" class="meter-bar"></div>
        </div>
        <p>Length: <span id="length"></span></p>
        <p>Contains lowercase: <span id="lower"></span></p>
        <p>Contains uppercase: <span id="upper"></span></p>
        <p>Contains digits: <span id="digit"></span></p>
        <p>Contains special chars: <span id="special"></span></p>
        <p>Common password: <span id="common"></span></p>
        <p>Entropy: <span id="entropy"></span> bits</p>
        <p>Strength: <span id="strength"></span>/10</p>
        <div id="recommendations"></div>
    </div>

    <h2>Cracking Demo</h2>
    <p>Enter a hash to test cracking (demo only - very limited):</p>
    <input type="text" id="hash" placeholder="Enter hash">
    <select id="algorithm">
        <option value="md5">MD5</option>
        <option value="sha1">SHA1</option>
        <option value="sha256" selected>SHA256</option>
        <option value="sha512">SHA512</option>
    </select>
    <select id="mode">
        <option value="dictionary">Dictionary</option>
        <option value="brute">Brute Force (very short)</option>
    </select>
    <button onclick="crack()">Test Crack</button>
    <div id="crack-result" style="margin-top: 20px;"></div>

    <script>
        function analyze() {
            const password = document.getElementById('password').value;
            fetch('/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `password=${encodeURIComponent(password)}`
            })
            .then(res => res.json())
            .then(data => {
                const result = document.getElementById('result');
                result.style.display = 'block';
                
                // Set strength class
                result.className = 'result ';
                if(data.strength < 4) result.className += 'weak';
                else if(data.strength < 7) result.className += 'medium';
                else result.className += 'strong';
                
                // Update fields
                document.getElementById('length').textContent = data.length;
                document.getElementById('lower').textContent = data.has_lower ? 'Yes' : 'No';
                document.getElementById('upper').textContent = data.has_upper ? 'Yes' : 'No';
                document.getElementById('digit').textContent = data.has_digit ? 'Yes' : 'No';
                document.getElementById('special').textContent = data.has_special ? 'Yes' : 'No';
                document.getElementById('common').textContent = data.is_common ? 'Yes' : 'No';
                document.getElementById('entropy').textContent = data.entropy;
                document.getElementById('strength').textContent = data.strength;
                document.getElementById('meter-bar').style.width = `${data.strength * 10}%`;
                
                // Recommendations
                let rec = '<h4>Recommendations:</h4><ul>';
                if(data.length < 8) rec += '<li>Use at least 8 characters</li>';
                if(!data.has_lower) rec += '<li>Add lowercase letters</li>';
                if(!data.has_upper) rec += '<li>Add uppercase letters</li>';
                if(!data.has_digit) rec += '<li>Add numbers</li>';
                if(!data.has_special) rec += '<li>Add special characters</li>';
                if(data.is_common) rec += '<li>Avoid common dictionary words</li>';
                rec += '</ul>';
                document.getElementById('recommendations').innerHTML = rec;
            });
        }
        
        function crack() {
            const hash = document.getElementById('hash').value;
            const algorithm = document.getElementById('algorithm').value;
            const mode = document.getElementById('mode').value;
            
            document.getElementById('crack-result').innerHTML = 'Cracking...';
            
            fetch('/crack', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hash, algorithm, mode })
            })
            .then(res => res.json())
            .then(data => {
                let result = '';
                if(data.found) {
                    result = `<p>Password cracked in ${data.time} seconds!</p>
                              <p>Password: <strong>${data.password}</strong></p>
                              <p>Attempts: ${data.attempts}</p>`;
                } else {
                    result = `<p>Password not found in demo attack</p>
                              <p>Attempts: ${data.attempts}</p>
                              <p>Time: ${data.time} seconds</p>`;
                }
                result += `<p><em>Note: This demo uses limited resources. Real cracking would use more powerful methods.</em></p>`;
                document.getElementById('crack-result').innerHTML = result;
            });
        }
    </script>
</body>
</html>''')
        app.run(debug=True)
