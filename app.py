import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pandas as pd
import numpy as np
import joblib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'threatintel_secret_key_123'
base_dir = os.path.dirname(os.path.abspath(__file__))
db_dir = os.path.join(base_dir, 'database')
os.makedirs(db_dir, exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(db_dir, 'threatintel.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Database Models ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='analyst')

class Threat(db.Model):
    __tablename__ = 'threats'
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(50), nullable=False) # Critical, High, Medium, Low
    source_ip = db.Column(db.String(50))
    status = db.Column(db.String(20), default='Active')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Load Models
def load_ml_models():
    models_dir = os.path.join(base_dir, 'models')
    try:
        scaler = joblib.load(os.path.join(models_dir, 'scaler.pkl'))
        target_encoder = joblib.load(os.path.join(models_dir, 'target_encoder.pkl'))
        rf_model = joblib.load(os.path.join(models_dir, 'xgb_model.pkl')) # using xgb for prediction
        
        # Load label encoders
        CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']
        label_encoders = {}
        for col in CATEGORICAL_COLS:
            label_encoders[col] = joblib.load(os.path.join(models_dir, f'encoder_{col}.pkl'))
            
        return scaler, target_encoder, rf_model, label_encoders
    except Exception as e:
        print("Models not found, proceeding without them.")
        return None, None, None, None

scaler, target_encoder, model, label_encoders = load_ml_models()

@app.before_request
def create_tables():
    app.before_request_funcs[None].remove(create_tables)
    db.create_all()

# --- Routes ---
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username exists')
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    total_threats = Threat.query.count()
    active_threats = Threat.query.filter_by(status='Active').count()
    critical_threats = Threat.query.filter_by(severity='Critical').count()
    malware_alerts = Threat.query.filter_by(category='Malware').count()
    
    return render_template('dashboard.html', 
                           total=total_threats, active=active_threats, 
                           critical=critical_threats, malware=malware_alerts)

from datetime import timedelta

@app.route('/api/chart-data')
def chart_data():
    # Auto-resolve threats older than 1 minute to make the dashboard feel "Live" and dynamic
    one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
    Threat.query.filter(Threat.timestamp < one_minute_ago, Threat.status == 'Active').update({'status': 'Resolved'})
    db.session.commit()

    # Get all threats for the "Total" metric
    all_threats = Threat.query.all()
    total = len(all_threats)
    
    # Only use ACTIVE threats for the live charts and other metrics
    active_threats = [t for t in all_threats if t.status == 'Active']
    active = len(active_threats)
    critical = sum(1 for t in active_threats if t.severity == 'Critical')
    malware = sum(1 for t in active_threats if t.category == 'Malware')
    
    categories = {}
    severities = {}
    for t in active_threats:
        categories[t.category] = categories.get(t.category, 0) + 1
        severities[t.severity] = severities.get(t.severity, 0) + 1
    
    return jsonify({
        'categories': categories,
        'severities': severities,
        'stats': {
            'total': total,
            'active': active,
            'critical': critical,
            'malware': malware
        }
    })

@app.route('/predict', methods=['POST'])
def predict():
    if not model or not scaler or not target_encoder or not label_encoders:
        return jsonify({'error': 'Models not loaded'})
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'})
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'})
        
    try:
        COLUMNS = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
           'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
           'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count',
           'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
           'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
           'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
           'label', 'difficulty']
        
        df = pd.read_csv(file, names=COLUMNS)
        if 'difficulty' in df.columns:
            df = df.drop('difficulty', axis=1)
        if 'label' in df.columns:
            df = df.drop('label', axis=1)
            
        df_sample = df.head(50).copy()
        
        CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']
        for col in CATEGORICAL_COLS:
            le = label_encoders.get(col)
            if le:
                df_sample[col] = df_sample[col].apply(lambda x: x if x in le.classes_ else le.classes_[0])
                df_sample[col] = le.transform(df_sample[col].astype(str))
                
        X_scaled = scaler.transform(df_sample)
        predictions_encoded = model.predict(X_scaled)
        predictions = target_encoder.inverse_transform(predictions_encoded)
        
        threats_added = 0
        for i, pred in enumerate(predictions):
            if pred != 'Normal':
                severity = 'Low'
                if pred in ['DDoS', 'Ransomware']: severity = 'Critical'
                elif pred in ['Malware', 'Insider Threat']: severity = 'High'
                elif pred in ['Port Scan', 'Brute Force']: severity = 'Medium'
                
                ip_address = f'192.168.1.{np.random.randint(1, 255)}'
                
                existing_threat = Threat.query.filter_by(category=pred, source_ip=ip_address, status='Active').first()
                if not existing_threat:
                    new_threat = Threat(
                        category=pred,
                        severity=severity,
                        source_ip=ip_address,
                    )
                    db.session.add(new_threat)
                    threats_added += 1
                
        db.session.commit()
        return jsonify({'status': 'success', 'message': f'File analyzed. {threats_added} new unique threats detected and logged.'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/threats')
def threats():
    if 'user_id' not in session: return redirect(url_for('login'))
    all_threats = Threat.query.order_by(Threat.timestamp.desc()).all()
    return render_template('threats.html', threats=all_threats)

@app.route('/alerts')
def alerts():
    if 'user_id' not in session: return redirect(url_for('login'))
    all_alerts = Alert.query.order_by(Alert.timestamp.desc()).all()
    return render_template('alerts.html', alerts=all_alerts)

@app.route('/analytics')
def analytics():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('analytics.html')

@app.route('/reports')
def reports():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    total_threats = Threat.query.count()
    active_threats = Threat.query.filter_by(status='Active').count()
    critical_threats = Threat.query.filter_by(severity='Critical').count()
    malware_alerts = Threat.query.filter_by(category='Malware').count()
    
    return render_template('reports.html', 
                           total=total_threats, active=active_threats, 
                           critical=critical_threats, malware=malware_alerts)

@app.route('/api/log_live_threats', methods=['POST'])
def log_live_threats():
    data = request.get_json()
    if not data or 'threats' not in data:
        return jsonify({'error': 'Invalid data'}), 400
        
    for t in data['threats']:
        category = t.get('category', 'Unknown')
        source_ip = t.get('source_ip', '127.0.0.1')
        
        # Remove duplicate: check if an active threat from this IP and category already exists
        existing_threat = Threat.query.filter_by(category=category, source_ip=source_ip, status='Active').first()
        if not existing_threat:
            new_threat = Threat(
                category=category,
                severity=t.get('severity', 'Low'),
                source_ip=source_ip
            )
            db.session.add(new_threat)
    db.session.commit()
    return jsonify({'status': 'success'})

import subprocess
import sys
sniffer_process = None

@app.route('/start_sniffer', methods=['POST'])
def start_sniffer():
    global sniffer_process
    if sniffer_process is None or sniffer_process.poll() is not None:
        script_path = os.path.join(base_dir, 'live_sniffer.py')
        sniffer_process = subprocess.Popen([sys.executable, script_path])
        return jsonify({'status': 'success', 'message': 'Live sniffer started!'})
    return jsonify({'status': 'info', 'message': 'Sniffer is already running.'})

@app.route('/api/reset', methods=['POST'])
def reset_data():
    if 'user_id' not in session: return jsonify({'error': 'Unauthorized'}), 401
    try:
        Threat.query.delete()
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'All threat data has been cleared.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
