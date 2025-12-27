# app.py - Flask web app for NetScaler automation
import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from netscaler import NetscalerClient, NetscalerError
from device_manager import device_manager

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "netscaler_audit.log")

# Logging
logger = logging.getLogger("app")
logger.setLevel(logging.INFO)
fh = logging.FileHandler(LOG_FILE)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
fh.setFormatter(formatter)
logger.addHandler(fh)

ns_logger = logging.getLogger("netscaler")
ns_logger.setLevel(logging.INFO)
ns_logger.addHandler(fh)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = "replace-with-secret-key"

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Simple user class (in production, use a proper user database)
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    @staticmethod
    def get(user_id):
        # Simple hardcoded user for demo (replace with database in production)
        users = {
            '1': User('1', 'admin', generate_password_hash('admin123')),
            '2': User('2', 'netscaler', generate_password_hash('netscaler123'))
        }
        return users.get(user_id)

    @staticmethod
    def get_by_username(username):
        users = {
            'admin': User('1', 'admin', generate_password_hash('admin123')),
            'netscaler': User('2', 'netscaler', generate_password_hash('netscaler123'))
        }
        return users.get(username)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.get_by_username(username)
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page or url_for('home'))
        else:
            flash('Invalid username or password', 'error')

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route("/")
@login_required
def home():
    return render_template("home.html")


@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "GET":
        devices = device_manager.get_all_devices()
        return render_template("create_vip.html", devices=devices)

    device_id = request.form.get("device_id")
    if not device_id:
        flash("Please select a device.", "danger")
        return redirect(url_for('create'))

    device = device_manager.get_device(device_id)
    if not device:
        flash(f"Device '{device_id}' not found.", "danger")
        return redirect(url_for('create'))

    vip_name = request.form.get("vip_name").strip()
    vip = request.form.get("vip").strip()
    vip_port = int(request.form.get("vip_port"))
    sg_name = request.form.get("sg_name") or f"sg_{vip_port}"
    servicetype = request.form.get("servicetype")
    nodes_raw = request.form.get("nodes")
    nodes = [n.strip() for n in nodes_raw.split(",") if n.strip()]
    monitor = request.form.get("monitor") or None
    certkey = request.form.get("certkey") or None

    logger.info("Create request: device=%s vip=%s vip_name=%s port=%s sg=%s nodes=%s monitor=%s cert=%s",
                device_id, vip, vip_name, vip_port, sg_name, nodes, monitor, certkey)

    try:
        ns = device_manager.get_client(device_id)
        if ns is None:
            flash(f"NetScaler device '{device['name']}' is not reachable. Operation skipped.", "warning")
            return redirect(url_for('create'))
    except NetscalerError as e:
        logger.warning("NetScaler device %s is not reachable: %s", device['host'], str(e))
        flash(f"NetScaler device '{device['name']}' is not reachable. Operation skipped.", "warning")
        return redirect(url_for('create'))
    try:
        # Validate monitor and certkey existence (friendly feedback)
        if monitor and not ns.monitor_exists(monitor):
            flash(f"Monitor {monitor} does not exist on NetScaler", "danger")
            return redirect(url_for('create'))
        if servicetype.upper() == "SSL" and certkey and not ns.certkey_exists(certkey):
            flash(f"CertKey {certkey} does not exist on NetScaler", "danger")
            return redirect(url_for('create'))

        result = ns.create_vip(
            vip_name=vip_name,
            vip=vip,
            vip_port=vip_port,
            servicetype=servicetype,
            sg_name=sg_name,
            nodes=nodes,
            monitor=monitor,
            certkey=certkey
        )

        vname = result['vip_name']
        added_members = result['added_members']
        failed_members = result['failed_members']

        flash(f"VIP {vname} created successfully", "success")

        if added_members:
            flash(f"Successfully added members: {', '.join(added_members)}", "info")

        if failed_members:
            flash(f"Skipped unreachable/invalid members: {', '.join(failed_members)}", "warning")
    except NetscalerError as e:
        logger.exception("Create failed")
        flash(f"Error: {e}", "danger")
    except Exception as e:
        logger.exception("Unexpected error")
        flash(f"Unexpected error: {e}", "danger")
    finally:
        if 'ns' in locals():
            ns.close()

    return redirect(url_for('create'))


@app.route("/dashboard")
@login_required
def dashboard():
    device_id = request.args.get("device_id", "default")

    device = device_manager.get_device(device_id)
    if not device:
        flash(f"Device '{device_id}' not found.", "danger")
        return redirect(url_for('home'))

    try:
        ns = device_manager.get_client(device_id)
        if ns is None:
            flash(f"NetScaler device '{device['name']}' is not reachable. Cannot load dashboard.", "warning")
            return redirect(url_for('home'))
    except NetscalerError as e:
        logger.warning("NetScaler device %s is not reachable: %s", device['host'], str(e))
        flash(f"NetScaler device '{device['name']}' is not reachable. Cannot load dashboard.", "warning")
        return redirect(url_for('home'))

    try:
        lbv = ns.get_lbvservers()
        # normalize for template
        lbv_list = []
        for v in lbv:
            lbv_list.append({
                "name": v.get("name"),
                "ipv46": v.get("ipv46"),
                "port": v.get("port"),
                "servicetype": v.get("servicetype"),
                "vsvrstate": v.get("vsvrstate", "UNKNOWN")
            })
        devices = device_manager.get_all_devices()
        return render_template("dashboard.html", lbvs=lbv_list, devices=devices, selected_device=device_id)
    except NetscalerError as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for('home'))
    finally:
        ns.close()


@app.route("/api/v1/vserver/<vname>", methods=["PUT"])
@login_required
def api_update_vserver(vname):
    device_id = request.args.get("device_id", "default")
    payload = request.json or {}

    device = device_manager.get_device(device_id)
    if not device:
        return jsonify({"error": f"Device '{device_id}' not found"}), 404

    try:
        ns = device_manager.get_client(device_id)
        if ns is None:
            return jsonify({"error": f"NetScaler device '{device['name']}' is not reachable"}), 503
    except NetscalerError as e:
        logger.warning("NetScaler device %s is not reachable: %s", device['host'], str(e))
        return jsonify({"error": f"NetScaler device '{device['name']}' is not reachable"}), 503

    try:
        ns.update_lbvserver(vname, **payload)
        return jsonify({"status": "ok"}), 200
    except NetscalerError as e:
        return jsonify({"error": str(e)}), 500
    finally:
        ns.close()


@app.route("/api/v1/vserver/<vname>", methods=["DELETE"])
@login_required
def api_delete_vserver(vname):
    device_id = request.args.get("device_id", "default")

    device = device_manager.get_device(device_id)
    if not device:
        return jsonify({"error": f"Device '{device_id}' not found"}), 404

    try:
        ns = device_manager.get_client(device_id)
        if ns is None:
            return jsonify({"error": f"NetScaler device '{device['name']}' is not reachable"}), 503
    except NetscalerError as e:
        logger.warning("NetScaler device %s is not reachable: %s", device['host'], str(e))
        return jsonify({"error": f"NetScaler device '{device['name']}' is not reachable"}), 503

    try:
        ns.delete_lbvserver(vname)
        return jsonify({"status": "deleted"}), 200
    except NetscalerError as e:
        return jsonify({"error": str(e)}), 500
    finally:
        ns.close()


@app.route("/devices", methods=["GET", "POST"])
@login_required
def manage_devices():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "add":
            device_id = request.form.get("device_id").strip()
            name = request.form.get("name").strip()
            host = request.form.get("host").strip()
            username = request.form.get("username").strip()
            password = request.form.get("password")
            description = request.form.get("description", "").strip()

            if not all([device_id, name, host, username, password]):
                flash("All fields are required.", "danger")
            elif device_manager.add_device(device_id, name, host, username, password, description):
                flash(f"Device '{name}' added successfully.", "success")
            else:
                flash(f"Device ID '{device_id}' already exists.", "warning")

        elif action == "remove":
            device_id = request.form.get("device_id")
            if device_manager.remove_device(device_id):
                flash(f"Device '{device_id}' removed successfully.", "success")
            else:
                flash(f"Device '{device_id}' not found.", "warning")

        elif action == "test":
            device_id = request.form.get("device_id")
            success, message = device_manager.test_device_connection(device_id)
            if success:
                flash(f"Connection to device '{device_id}' successful.", "success")
            else:
                flash(f"Connection to device '{device_id}' failed: {message}", "warning")

        return redirect(url_for('manage_devices'))

    devices = device_manager.get_all_devices()
    return render_template("devices.html", devices=devices)

@app.route("/health")
def health():
    return "ok", 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
