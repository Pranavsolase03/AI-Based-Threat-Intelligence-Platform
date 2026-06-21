# AI-Based Threat Intelligence Platform

A comprehensive, full-stack cybersecurity platform that utilizes Machine Learning to detect, analyze, and visualize network threats in real-time. Built with a Flask backend, an XGBoost ML pipeline trained on the NSL-KDD dataset, and a modern, minimalistic glassmorphism dashboard.

## 🚀 Features

- **Live Laptop Network Sniffing**: Safely captures local network connections using `psutil`, maps them to NSL-KDD features, and evaluates them continuously for real-time threat detection.
- **Log File Analysis**: Manually upload `.csv` or `.txt` log files directly through the dashboard to instantly analyze historical network data.
- **Dynamic Threat Dashboard**: Real-time charts powered by Chart.js that auto-refresh to show Active Threats, Critical Alerts, and Severity Distributions over the last 60 seconds.
- **Automated ML Pipeline**: Pre-trained ensemble models (XGBoost, Random Forest, Isolation Forest) map network flows to categorizations like DDoS, Port Scan, Malware, and Normal traffic.
- **Sleek Minimal UI**: A professional, enterprise-grade interface tailored for Security Operations Centers (SOC) and cyber analysts.
- **One-Click Reset**: Instantly clear databases and analytics metrics directly from the UI for fresh testing runs.

## 🛠️ Technology Stack

**Frontend:**
- HTML5, CSS3, JavaScript
- Bootstrap 5
- Chart.js (Interactive Data Visualization)
- FontAwesome (Icons)

**Backend:**
- Python 3.10+
- Flask (Web Framework & REST API)
- SQLite (Relational Database via SQLAlchemy)
- psutil (Live system/network data extraction)

**Machine Learning:**
- Pandas & NumPy (Data processing)
- Scikit-Learn (Preprocessing, Encoders, Scalers)
- XGBoost (Core threat classification model)
- TensorFlow / Keras (Neural Network models)
- Joblib (Model serialization)

---

## ⚙️ Installation & Setup

### Prerequisites
Make sure you have Python 3.8+ installed on your system. You will also need `pip` installed.

### 1. Clone the Repository
If you haven't already, clone or download the project files to your local machine.

### 2. Create a Virtual Environment
It is highly recommended to run this project inside an isolated virtual environment to prevent dependency conflicts.
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
Install all required Python libraries using the provided `requirements.txt` file.
```bash
pip install -r requirements.txt
```

### 4. Database Initialization
The SQLite database (`threatintel.db`) will be automatically created in the `database/` folder the first time you run the application.

---

## 🏃 Running the Application

### 1. Start the Flask Server
Ensure your virtual environment is activated, then run the main application file:
```bash
python app.py
```
The server will start on `http://127.0.0.1:5000` (or `http://localhost:5000`).

### 2. Access the Dashboard
Open your web browser and navigate to `http://localhost:5000`. You will be greeted by the Login page. 
*(If authentication is bypassed for development, navigate directly to `/dashboard`)*.

---

## 📡 Using the Live Sniffer

The Live Sniffer monitors your laptop's actual active network connections, constructs ML-ready feature arrays, and uses the pre-trained XGBoost model to evaluate them.

1. Navigate to the **Dashboard**.
2. Click the yellow **Start Live Sniffer** button.
3. A background process (`live_sniffer.py`) will automatically start monitoring your network traffic.
4. The dashboard charts and top metrics will **auto-refresh every 5 seconds**.
5. *Note: For demonstration purposes, the sniffer randomly injects anomalous "DDoS" signatures into your safe local traffic to guarantee the ML model triggers alerts on the dashboard.*

## 📂 Project Structure

```text
├── app.py                  # Main Flask API and application routing
├── live_sniffer.py         # Background daemon for real-time network capture
├── requirements.txt        # Project dependencies
├── database/
│   └── threatintel.db      # SQLite Database (Auto-generated)
├── models/                 # Serialized ML Models
│   ├── xgb_model.pkl       # Core XGBoost Classifier
│   ├── scaler.pkl          # Feature Scaler
│   └── encoder_*.pkl       # Label Encoders
├── static/
│   ├── css/style.css       # Clean, minimalistic UI styles
│   └── js/dashboard.js     # Frontend logic, API fetching, Chart rendering
└── templates/              # Jinja2 HTML Templates
    ├── base.html           # Main layout wrapper
    ├── dashboard.html      # Primary Analytics View
    ├── threats.html        # Detailed Threat Database Table
    └── alerts.html         # Live Alert Feed
```

## ⚠️ Important Notes
- This platform relies on models trained via the **NSL-KDD** dataset.
- The `live_sniffer.py` script utilizes `psutil` instead of complex packet capture engines (like WinPcap/Npcap or Zeek) to remain lightweight, cross-platform, and entirely safe for local laptop demonstrations.
