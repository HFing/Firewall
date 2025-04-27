from flask import Flask, render_template, request, redirect, url_for, flash, abort, make_response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from config import Config
from models import db, User
import boto3
import json
from datetime import datetime
import random

# ======= APP SETUP =======
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ======= AWS SETUP =======
client = boto3.client(
    'network-firewall',
    region_name='ap-southeast-1',
    aws_access_key_id='AKIA2T56GOP4O5RXFUNM',
    aws_secret_access_key='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'
)

logs_client = boto3.client(
    'logs',
    region_name='ap-southeast-1',
    aws_access_key_id='AKIA2T56GOP4O5RXFUNM',
    aws_secret_access_key='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'
)

FIREWALL_NAME = "firewallfwaas"
RULE_GROUP_NAME = "block-dns-https"
LOG_GROUP_NAME = "network-firewall-logs"


# ======= LOGIN MANAGER =======
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def is_admin():
    return current_user.is_authenticated and current_user.role == 'admin'


# ======= AWS FUNCTIONS =======
def get_logs_from_cloudwatch():
    try:
        streams_response = logs_client.describe_log_streams(
            logGroupName=LOG_GROUP_NAME,
            orderBy='LastEventTime',
            descending=True,
            limit=1
        )
        latest_stream = streams_response['logStreams'][0]['logStreamName']
        logs_response = logs_client.get_log_events(
            logGroupName=LOG_GROUP_NAME,
            logStreamName=latest_stream,
            limit=50
        )
        parsed_logs = []
        for event in logs_response['events']:
            try:
                raw_log = json.loads(event['message'])
                netflow_info = raw_log['event'].get('netflow', {})
                action = "Block" if netflow_info.get('alerted') else "Allow"
                parsed_logs.append({
                    'timestamp': datetime.utcfromtimestamp(int(raw_log['event_timestamp'])).strftime(
                        '%Y-%m-%d %H:%M:%S'),
                    'src_ip': raw_log['event'].get('src_ip', 'Unknown'),
                    'dest_ip': raw_log['event'].get('dest_ip', 'Unknown'),
                    'action': action
                })
            except Exception as e:
                print(f"Lỗi parse log: {e}")
        return parsed_logs
    except Exception as e:
        print(f"Lỗi lấy logs: {e}")
        return []


def get_current_rules():
    response = client.describe_rule_group(
        RuleGroupName=RULE_GROUP_NAME,
        Type='STATEFUL'
    )
    rules_string = response['RuleGroup']['RulesSource']['RulesString']
    rules = rules_string.strip().split('\n')
    return rules


def update_rules_to_aws(rules):
    new_rules_string = '\n'.join(rules)
    describe_response = client.describe_rule_group(
        RuleGroupName=RULE_GROUP_NAME,
        Type='STATEFUL'
    )
    rule_group = describe_response['RuleGroup']
    rule_group['RulesSource'] = {'RulesString': new_rules_string}
    client.update_rule_group(
        RuleGroupArn=describe_response['RuleGroupResponse']['RuleGroupArn'],
        UpdateToken=describe_response['UpdateToken'],
        RuleGroup=rule_group
    )


# ======= AUTH ROUTES =======
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Đăng nhập thất bại.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email đã tồn tại.', 'warning')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, email=email, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Đăng ký thành công.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ======= FIREWALL ROUTES =======

@app.route('/')
def index():
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
@login_required
def dashboard():
    total_rules = len(get_current_rules())
    allow_rules = sum(1 for r in get_current_rules() if 'pass' in r)
    block_rules = total_rules - allow_rules
    return render_template('dashboard.html', total_rules=total_rules, allow_rules=allow_rules, block_rules=block_rules)


@app.route('/rules')
@login_required
def rules():
    current_rules = get_current_rules()
    return render_template('rules.html', current_rules=current_rules, is_admin=is_admin())


@app.route('/add_rule', methods=['POST'])
@login_required
def add_rule():
    if not is_admin():
        abort(403)

    protocol = request.form['protocol']
    port = request.form['port']
    action = request.form['action']
    sid = random.randint(100000, 999999)
    rule = f"{action} {protocol} any any -> any {port} (msg:\"{action.upper()} {protocol.upper()} Port {port}\"; sid:{sid};)"

    rules = get_current_rules()
    rules.append(rule)
    update_rules_to_aws(rules)

    return redirect(url_for('rules'))


@app.route('/edit_rule/<int:rule_id>', methods=['GET', 'POST'])
@login_required
def edit_rule(rule_id):
    if not is_admin():
        abort(403)

    rules = get_current_rules()
    if request.method == 'POST':
        protocol = request.form['protocol']
        port = request.form['port']
        action = request.form['action']
        sid = random.randint(100000, 999999)
        new_rule = f"{action} {protocol} any any -> any {port} (msg:\"{action.upper()} {protocol.upper()} Port {port}\"; sid:{sid};)"
        rules[rule_id] = new_rule
        update_rules_to_aws(rules)
        return redirect(url_for('rules'))

    old_rule = rules[rule_id]
    parts = old_rule.split()

    # Validate the rule format
    if len(parts) < 7:
        flash("Invalid rule format. Unable to edit.", "danger")
        return redirect(url_for('rules'))

    action = parts[0]
    protocol = parts[1]
    port = parts[6]

    return render_template('edit_rule.html', rule_id=rule_id, protocol=protocol, port=port, action=action)


@app.route('/delete_rule/<int:rule_id>')
@login_required
def delete_rule(rule_id):
    if not is_admin():
        abort(403)

    rules = get_current_rules()
    if rule_id < len(rules):
        rules.pop(rule_id)
        update_rules_to_aws(rules)
    return redirect(url_for('rules'))


@app.route('/export_rules')
@login_required
def export_rules():
    rules = get_current_rules()
    output = "\n".join(rules)
    response = make_response(output)
    response.headers["Content-Disposition"] = "attachment; filename=rules.txt"
    response.headers["Content-Type"] = "text/plain"
    return response



@app.route('/logs')
def logs():
    logs_list = get_logs_from_cloudwatch()
    return render_template('logs.html', logs=logs_list)

@app.route('/threats')
def threats():
    logs = get_logs_from_cloudwatch()
    ip_counter = {}

    for log in logs:
        src_ip = log.get('src_ip')
        if src_ip:
            ip_counter[src_ip] = ip_counter.get(src_ip, 0) + 1

    detected_threats = []
    for ip, count in ip_counter.items():
        if count > 10:  # Nếu IP xuất hiện > 10 lần thì nghi ngờ
            detected_threats.append({
                'ip': ip,
                'count': count,
                'ports': ['unknown'],
                'type': 'Port Scan' if count > 20 else 'Suspicious'
            })

    return render_template('threats.html', detected_threats=detected_threats)


# ========= MAIN =========
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

