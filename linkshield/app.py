"""
LinkShield — Flask Web Application
Fake Login Page & Phishing URL Detector
"""

from flask import Flask, render_template, request, jsonify
from phishing_analyzer import analyze_url

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    try:
        result = analyze_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Invalid URL format: {str(e)}'}), 400


if __name__ == '__main__':
    app.run(debug=True, port=5000)
