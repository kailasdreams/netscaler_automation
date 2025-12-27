# NetScaler Automation Portal (ZIP)
This package contains a Flask-based portal and a NetScaler NITRO client for automating VIP creation,
service groups, monitor and SSL bindings on NetScaler ADC (tested for 14.x).

## Quick start
1. Update `config.py` with your NetScaler host and credentials.
2. Create a virtualenv: `python -m venv venv && source venv/bin/activate`
3. Install deps: `pip install -r requirements.txt`
4. Run: `python app.py`
5. Open `http://127.0.0.1:5000`

## Notes
- For production, do NOT store credentials in `config.py`. Use environment variables or a secrets manager.
- The NitRO API requires network reachability to your ADC from the machine running this app.
