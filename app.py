from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import math

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secure random key

# Initialize database
def init_db():
    conn = sqlite3.connect('fmea.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS failure_modes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  step TEXT,
                  failure_mode TEXT,
                  cause TEXT,
                  control TEXT,
                  effect TEXT,
                  s INTEGER,
                  o INTEGER,
                  d INTEGER,
                  rpn INTEGER,
                  form_type TEXT,
                  user_id INTEGER,
                  FOREIGN KEY (user_id) REFERENCES users(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password TEXT)''')
    conn.commit()
    conn.close()

# Seed database with sample data for a specific user
def seed_db():
    conn = sqlite3.connect('fmea.db')
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', ('testuser',))
    user = c.fetchone()
    if not user:
        hashed_pw = generate_password_hash('testpass')
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('testuser', hashed_pw))
        conn.commit()
        user_id = c.lastrowid
    else:
        user_id = user[0]
    
    c.execute('SELECT COUNT(*) FROM failure_modes WHERE user_id = ?', (user_id,))
    if c.fetchone()[0] == 0:
        sample_data = [
            ('Donor Registration', 'Incorrect data entry', 'Human error', 'Double-check', 'Delayed process', 5, 4, 3, 60, 'Blood Donation', user_id),
            ('Patient Identification', 'Wrong patient ID', 'Miscommunication', 'ID verification', 'Transfusion error', 8, 5, 4, 160, 'Blood Transfusion', user_id),
            ('Medical history of donor', 'Incomplete history', 'Donor omission', 'Checklist', 'Health risks', 6, 3, 2, 36, 'Blood Donation', user_id),
            ('Sampling', 'Contaminated sample', 'Poor technique', 'Training', 'Inaccurate results', 7, 4, 3, 84, 'Blood Transfusion', user_id),
            ('Blood Collection', 'Improper needle insertion', 'Lack of training', 'Training protocol', 'Donor injury', 7, 3, 3, 63, 'Blood Donation', user_id),
            ('Transfusion Setup', 'Incorrect blood type', 'Labeling error', 'Cross-check', 'Patient harm', 9, 4, 5, 180, 'Blood Transfusion', user_id)
        ]
        c.executemany('INSERT INTO failure_modes (step, failure_mode, cause, control, effect, s, o, d, rpn, form_type, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', sample_data)
        conn.commit()
    conn.close()

# Retrieve filtered data for tables and charts (user-specific)
def get_filtered_data(user_id, form_type='all', rpn_threshold=60):
    conn = sqlite3.connect('fmea.db')
    c = conn.cursor()
    query = 'SELECT step, failure_mode, s, o, d, rpn, form_type FROM failure_modes WHERE user_id = ?'
    params = [user_id]
    if form_type != 'all':
        query += ' AND form_type = ?'
        params.append(form_type)
    c.execute(query, params)
    rows = c.fetchall()
    data = [{
        'Step': row[0] or '',
        'Failure Mode': row[1] or '',
        'S': row[2] or 0,
        'O': row[3] or 0,
        'D': row[4] or 0,
        'RPN': row[5] or 0,
        'Form Type': row[6] or ''
    } for row in rows]
    conn.close()
    
    top_5 = [item for item in data if item['RPN'] > rpn_threshold]
    top_5 = sorted(top_5, key=lambda x: x['RPN'], reverse=True)[:10]
    
    # Dynamic risk ranges with validation
    medium_lower = max(1, math.floor(rpn_threshold / 2))  # Ensure medium_lower is at least 1
    risk_dist = {
        f'Low (0-{medium_lower-1})': len([item for item in data if item['RPN'] <= medium_lower-1]),
        f'Medium ({medium_lower}-{rpn_threshold})': len([item for item in data if medium_lower <= item['RPN'] <= rpn_threshold]),
        f'High (>{rpn_threshold})': len([item for item in data if item['RPN'] > rpn_threshold])
    }
    
    print(f'Filtered data for user {user_id}: data={len(data)} entries, Top 5={len(top_5)}, Risk dist={risk_dist}, Threshold={rpn_threshold}, Medium lower={medium_lower}')
    return data, top_5, risk_dist

# Login required decorator
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect('fmea.db')
        c = conn.cursor()
        
        if action == 'signup':
            try:
                hashed_pw = generate_password_hash(password)
                c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_pw))
                conn.commit()
                user_id = c.lastrowid
                session['user_id'] = user_id
                session['username'] = username
                return redirect(url_for('home'))
            except sqlite3.IntegrityError:
                error = 'Username already exists.'
        
        elif action == 'signin':
            c.execute('SELECT id, password FROM users WHERE username = ?', (username,))
            row = c.fetchone()
            if row and check_password_hash(row[1], password):
                session['user_id'] = row[0]
                session['username'] = username
                return redirect(url_for('home'))
            else:
                error = 'Invalid username or password.'
        
        conn.close()
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/form_transfusion', methods=['GET', 'POST'])
@login_required
def form_transfusion():
    error = None
    success = None
    rpn = None
    if request.method == 'POST':
        step = request.form.get('step')
        failure_mode = request.form.get('failure_mode')
        cause = request.form.get('cause')
        control = request.form.get('control')
        effect = request.form.get('effect')
        form_type = "Blood Transfusion"
        user_id = session['user_id']
        try:
            s = int(request.form.get('severity'))
            o = int(request.form.get('occurrence'))
            d = int(request.form.get('detection'))
        except (TypeError, ValueError):
            error = 'Severity, Occurrence, and Detection must be numbers between 1 and 10.'
            return render_template('form_transfusion.html', error=error, success=success, rpn=rpn)

        if not all([step, failure_mode, cause, control, effect, s, o, d]):
            error = 'All fields are required.'
            return render_template('form_transfusion.html', error=error, success=success, rpn=rpn)
        if not (1 <= s <= 10 and 1 <= o <= 10 and 1 <= d <= 10):
            error = 'Values must be between 1 and 10.'
            return render_template('form_transfusion.html', error=error, success=success, rpn=rpn)

        rpn = s * o * d
        conn = sqlite3.connect('fmea.db')
        c = conn.cursor()
        c.execute('INSERT INTO failure_modes (step, failure_mode, cause, control, effect, s, o, d, rpn, form_type, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                  (step, failure_mode, cause, control, effect, s, o, d, rpn, form_type, user_id))
        conn.commit()
        conn.close()
        success = f'Failure mode added successfully! Calculated RPN: {rpn}'
        return render_template('form_transfusion.html', error=error, success=success, rpn=rpn)
    return render_template('form_transfusion.html', error=error, success=success, rpn=rpn)

@app.route('/form_donation', methods=['GET', 'POST'])
@login_required
def form_donation():
    error = None
    success = None
    rpn = None
    if request.method == 'POST':
        step = request.form.get('step')
        failure_mode = request.form.get('failure_mode')
        cause = request.form.get('cause')
        control = request.form.get('control')
        effect = request.form.get('effect')
        form_type = "Blood Donation"
        user_id = session['user_id']
        try:
            s = int(request.form.get('severity'))
            o = int(request.form.get('occurrence'))
            d = int(request.form.get('detection'))
        except (TypeError, ValueError):
            error = 'Severity, Occurrence, and Detection must be numbers between 1 and 10.'
            return render_template('form_donation.html', error=error, success=success, rpn=rpn)

        if not all([step, failure_mode, cause, control, effect, s, o, d]):
            error = 'All fields are required.'
            return render_template('form_donation.html', error=error, success=success, rpn=rpn)
        if not (1 <= s <= 10 and 1 <= o <= 10 and 1 <= d <= 10):
            error = 'Values must be between 1 and 10.'
            return render_template('form_donation.html', error=error, success=success, rpn=rpn)

        rpn = s * o * d
        conn = sqlite3.connect('fmea.db')
        c = conn.cursor()
        c.execute('INSERT INTO failure_modes (step, failure_mode, cause, control, effect, s, o, d, rpn, form_type, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                  (step, failure_mode, cause, control, effect, s, o, d, rpn, form_type, user_id))
        conn.commit()
        conn.close()
        success = f'Failure mode added successfully! Calculated RPN: {rpn}'
        return render_template('form_donation.html', error=error, success=success, rpn=rpn)
    return render_template('form_donation.html', error=error, success=success, rpn=rpn)

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    data, top_5, risk_dist = get_filtered_data(user_id)
    return render_template('dashboard.html', data=data, top_5=top_5, risk_dist=risk_dist, form_type='all', rpn_threshold=60)

@app.route('/api/dashboard_data', methods=['POST'])
@login_required
def dashboard_data():
    user_id = session['user_id']
    form_type = request.form.get('form_type', 'all')
    rpn_threshold = request.form.get('rpn_threshold', 60, type=int)
    if rpn_threshold < 0:
        return jsonify({'error': 'RPN threshold must be non-negative.'}), 400
    data, top_5, risk_dist = get_filtered_data(user_id, form_type, rpn_threshold)
    return jsonify({
        'data': data,
        'top_5': top_5,
        'risk_dist': risk_dist,
        'form_type': form_type,
        'rpn_threshold': rpn_threshold
    })

@app.route('/reports')
@login_required
def reports():
    user_id = session['user_id']
    data = get_filtered_data(user_id)[0]
    return render_template('reports.html', data=data)

if __name__ == '__main__':
    init_db()
    seed_db()
    app.run(debug=True)