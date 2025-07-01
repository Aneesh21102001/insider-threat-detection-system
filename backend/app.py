from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask import send_from_directory
from model.detect import predict_threat
import sys
import logging
import csv
from datetime import datetime
import os
import pandas as pd

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure SQLite DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///insider_threat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define a Log model
class DetectionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80))
    resource_accessed = db.Column(db.String(120))
    action = db.Column(db.String(120))
    data_transferred = db.Column(db.Integer)
    threat = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Create tables
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return jsonify({"message": "Insider Threat Detection API running"}), 200

@app.route('/detect', methods=['POST'])
def detect():
    data = request.json
    logging.info(f"Received: {data}")
    try:
        result = predict_threat(data)
        logging.info(f"Prediction: {result}")

        # CSV Logging Setup
        if not os.path.exists('logs'):
            os.makedirs('logs')
        log_file_path = 'logs/threat_log.csv'

        # Add header only if file is new
        write_header = not os.path.exists(log_file_path)

        with open(log_file_path, mode='a', newline='') as file:
            writer = csv.writer(file)
            if write_header:
                writer.writerow(["timestamp", "user_id", "resource_accessed", "action", "data_transferred", "threat"])
            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                data.get('user_id'),
                data.get('resource_accessed'),
                data.get('action'),
                data.get('data_transferred'),
                result
            ])

        return jsonify({'status': 'success', 'threat': result})
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    user_id = request.args.get('user_id')

    if not user_id:
        user_id = request.remote_addr  # fallback if user_id not passed

    file_path = os.path.join('files', filename)

    if not os.path.exists(file_path):
        return jsonify({'status': 'error', 'message': 'File not found'}), 404

    # Threat logic
    size_in_bytes = os.path.getsize(file_path)
    size_in_kb = round(size_in_bytes / 1024, 2)
    data_transferred = f"{size_in_kb}KB"
    threat = "malicious" if size_in_kb > 1024 else "normal"

    # Logging to CSV
    log_file_path = 'logs/threat_log.csv'
    if not os.path.exists('logs'):
        os.makedirs('logs')
    write_header = not os.path.exists(log_file_path)

    with open(log_file_path, mode='a', newline='') as file:
        writer = csv.writer(file)
        if write_header:
            writer.writerow(["timestamp", "user_id", "resource_accessed", "action", "data_transferred", "threat"])
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            user_id,
            filename,
            "download",
            data_transferred,
            threat
        ])

    return send_from_directory('files', filename, as_attachment=True)

# Sample insider threat logs data
logs_data = [
    {
        "timestamp": "2025-05-29T10:15:00Z",
        "user_id": "user123",
        "resource_accessed": "Financial_Report.pdf",
        "action": "download",
        "data_transferred": "2MB",
        "threat": "normal"
    },
    {
        "timestamp": "2025-05-29T11:30:00Z",
        "user_id": "user456",
        "resource_accessed": "Confidential_Strategy.docx",
        "action": "edit",
        "data_transferred": "500KB",
        "threat": "malicious"
    },
    {
        "timestamp": "2025-05-29T12:00:00Z",
        "user_id": "user789",
        "resource_accessed": "Employee_Data.csv",
        "action": "upload",
        "data_transferred": "1MB",
        "threat": "normal"
    }
]

@app.route('/logs', methods=['GET'])
def get_logs():
    try:
        log_file_path = 'logs/threat_log.csv'
        if not os.path.exists(log_file_path):
            return jsonify([])
        df = pd.read_csv(log_file_path)
        return jsonify(df.to_dict(orient='records'))
    except Exception as e:
        logging.error(f"Error reading logs: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
