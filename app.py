import os
import sqlite3
import secrets
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, g, render_template, redirect, url_for, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['DATABASE'] = os.path.join(app.root_path, 'erp.db')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)


# ==============================================================================
# DATABASE SETUP
# ==============================================================================
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys = ON')
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None: db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute(
            'CREATE TABLE IF NOT EXISTS companies (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, is_active INTEGER DEFAULT 1)')
        db.execute(
            'CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL, username TEXT NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL, last_login TEXT, FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE, UNIQUE(username))')
        db.execute(
            'CREATE TABLE IF NOT EXISTS locations (id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL, address TEXT, FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE, UNIQUE(company_id, name))')
        db.execute(
            'CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL, name TEXT NOT NULL, brand TEXT, description TEXT, price REAL NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE, UNIQUE(company_id, name, brand))')
        db.execute(
            'CREATE TABLE IF NOT EXISTS inventory (id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL, product_id INTEGER NOT NULL, location_id INTEGER NOT NULL, quantity INTEGER NOT NULL, last_updated TEXT NOT NULL, FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE, FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE, FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE CASCADE, UNIQUE(product_id, location_id))')
        db.execute(
            'CREATE TABLE IF NOT EXISTS transfers (id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL, product_id INTEGER NOT NULL, from_location_id INTEGER NOT NULL, to_location_id INTEGER NOT NULL, quantity INTEGER NOT NULL, status TEXT NOT NULL, initiated_by INTEGER NOT NULL, created_at TEXT NOT NULL, completed_at TEXT, FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE, FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE, FOREIGN KEY (from_location_id) REFERENCES locations(id) ON DELETE CASCADE, FOREIGN KEY (to_location_id) REFERENCES locations(id) ON DELETE CASCADE, FOREIGN KEY (initiated_by) REFERENCES users(id) ON DELETE CASCADE)')
        db.execute(
            'CREATE TABLE IF NOT EXISTS sales (id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL, customer_name TEXT, location_id INTEGER NOT NULL, total_amount REAL NOT NULL, created_by INTEGER NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE, FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE CASCADE, FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE)')
        db.execute(
            'CREATE TABLE IF NOT EXISTS sale_items (id INTEGER PRIMARY KEY, sale_id INTEGER NOT NULL, product_id INTEGER NOT NULL, quantity INTEGER NOT NULL, unit_price REAL NOT NULL, company_id INTEGER NOT NULL, FOREIGN KEY (sale_id) REFERENCES sales(id) ON DELETE CASCADE, FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE, FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE)')
        db.commit()


def seed_new_company(db, company_id):
    locations = [('Main Warehouse', 'warehouse', '', company_id), ('Main Showroom', 'showroom', '', company_id),
                 ('Project Site A', 'project', '', company_id)]
    db.executemany('INSERT INTO locations (name, type, address, company_id) VALUES (?, ?, ?, ?)', locations);
    db.commit()


# ==============================================================================
# DECORATORS & AUTH API
# ==============================================================================
def api_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: return jsonify(
            {'error': 'Authentication session expired. Please log in again.'}), 401
        return f(*args, **kwargs)

    return decorated_function


def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('user_role') not in roles: return jsonify(
                {'error': 'Insufficient permissions for this action.'}), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'DELETE'):
            if request.headers.get('X-CSRF-Token') != session.get('csrf_token'): return jsonify(
                {'error': 'Invalid security token. Please refresh the page.'}), 403
        return f(*args, **kwargs)

    return decorated_function


@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json();
    c_name, uname, pwd = data.get('company_name'), data.get('username'), data.get('password')
    if not all([c_name, uname, pwd]): return jsonify({'error': 'Missing fields'}), 400
    db = get_db()
    try:
        cursor = db.execute('INSERT INTO companies (name, created_at) VALUES (?, ?)',
                            (c_name, datetime.now().isoformat()));
        cid = cursor.lastrowid
        db.execute('INSERT INTO users (company_id, username, password, role, created_at) VALUES (?, ?, ?, ?, ?)',
                   (cid, uname, generate_password_hash(pwd), 'admin', datetime.now().isoformat()))
        seed_new_company(db, cid);
        db.commit();
        return jsonify({'message': 'Company registered successfully.'}), 201
    except sqlite3.IntegrityError:
        db.rollback(); return jsonify({'error': 'Company name or email already exists.'}), 409


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json();
    uname, pwd, role = data.get('username'), data.get('password'), data.get('role')
    if not all([uname, pwd, role]): return jsonify({'error': 'Missing credentials'}), 400
    db = get_db();
    user = db.execute('SELECT * FROM users WHERE username = ?', (uname,)).fetchone()
    if not user or not check_password_hash(user['password'], pwd): return jsonify({'error': 'Invalid credentials'}), 401
    if user['role'] != role: return jsonify({'error': f"You are not registered as '{role}'."}), 403
    company = db.execute('SELECT name FROM companies WHERE id = ?', (user['company_id'],)).fetchone()
    db.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now().isoformat(), user['id']));
    db.commit()
    session.permanent = True;
    session.update(user_id=user['id'], username=user['username'], user_role=user['role'], company_id=user['company_id'],
                   company_name=company['name'], csrf_token=secrets.token_hex(16))
    return jsonify({'message': 'Login successful'})


@app.route('/api/logout', methods=['POST'])
def api_logout(): session.clear(); return jsonify({'message': 'Logout successful'})


@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if 'user_id' in session: return jsonify({'authenticated': True,
                                             'user': {'id': session['user_id'], 'username': session['username'],
                                                      'role': session['user_role'],
                                                      'company_name': session['company_name']}})
    return jsonify({'authenticated': False})


@app.route('/api/csrf-token', methods=['GET'])
@api_login_required
def get_csrf_token(): return jsonify({'csrf_token': session.get('csrf_token')})


@app.route('/api/users', methods=['GET'])
@api_login_required
@role_required(['admin'])
def get_users(): return jsonify([dict(u) for u in get_db().execute(
    'SELECT id, username, role, created_at FROM users WHERE company_id = ? ORDER BY role, username',
    (session['company_id'],)).fetchall()])


@app.route('/api/users', methods=['POST'])
@api_login_required
@role_required(['admin'])
@csrf_protect
def add_user():
    data = request.get_json();
    username, password, role = data.get('username'), data.get('password'), data.get('role')
    if not all([username, password, role]) or role not in ['warehouse', 'showroom']: return jsonify(
        {'error': 'Missing/invalid fields.'}), 400
    db = get_db()
    try:
        db.execute('INSERT INTO users (company_id, username, password, role, created_at) VALUES (?, ?, ?, ?, ?)', (
        session['company_id'], username, generate_password_hash(password), role, datetime.now().isoformat()));
        db.commit()
        return jsonify({'message': 'User added.'}), 201
    except sqlite3.IntegrityError:
        db.rollback(); return jsonify({'error': 'Username already exists.'}), 409


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@api_login_required
@role_required(['admin'])
@csrf_protect
def delete_user(user_id):
    if user_id == session['user_id']: return jsonify({'error': 'Cannot delete yourself.'}), 400
    db = get_db();
    user = db.execute('SELECT username FROM users WHERE id = ? AND company_id = ?',
                      (user_id, session['company_id'])).fetchone()
    if not user: return jsonify({'error': 'User not found.'}), 404
    db.execute('DELETE FROM users WHERE id = ?', (user_id,));
    db.commit();
    return jsonify({'message': 'User deleted.'})


# ==============================================================================
# CORE ERP API (ALL ORIGINAL ENDPOINTS RESTORED AND FIXED)
# ==============================================================================
@app.route('/api/locations', methods=['GET'])
@api_login_required
def get_locations(): return jsonify([dict(r) for r in
                                     get_db().execute('SELECT id, name, type FROM locations WHERE company_id = ?',
                                                      (session['company_id'],)).fetchall()])


@app.route('/api/products', methods=['GET'])
@api_login_required
def get_products(): return jsonify([dict(r) for r in
                                    get_db().execute('SELECT * FROM products WHERE company_id = ? ORDER BY name',
                                                     (session['company_id'],)).fetchall()])


@app.route('/api/inventory', methods=['GET', 'POST'])
@api_login_required
@csrf_protect
def handle_inventory():
    db = get_db();
    cid = session['company_id']
    if request.method == 'GET':
        args, per_page = request.args, 10;
        location_id, search, page = args.get('location_id', 'all'), args.get('search', ''), args.get('page', 1,
                                                                                                     type=int)
        base_q = "SELECT i.id, p.id as product_id, p.name, p.brand, l.name as location_name, i.quantity, i.last_updated FROM inventory i JOIN products p ON i.product_id = p.id JOIN locations l ON i.location_id = l.id WHERE i.company_id = ? AND (p.name LIKE ? OR p.brand LIKE ?)";
        params = [cid, f'%{search}%', f'%{search}%']
        if location_id != 'all': base_q += " AND i.location_id = ?"; params.append(location_id)
        total = db.execute(f"SELECT COUNT(*) FROM ({base_q})", params).fetchone()[0]
        items = db.execute(base_q + " ORDER BY p.name LIMIT ? OFFSET ?",
                           params + [per_page, (page - 1) * per_page]).fetchall()
        return jsonify({'data': [dict(i) for i in items],
                        'pagination': {'page': page, 'total_pages': (total + per_page - 1) // per_page,
                                       'total': total}})

    if request.method == 'POST':
        if session['user_role'] not in ['admin', 'warehouse']: return jsonify({'error': 'Unauthorized'}), 403
        data = request.get_json();
        name, brand, loc_id, qty = data.get('name'), data.get('brand'), data.get('location_id'), data.get('quantity')
        if not all([name, brand, loc_id, qty]): return jsonify({'error': 'Missing fields'}), 400
        try:
            now = datetime.now().isoformat();
            prod = db.execute("SELECT id FROM products WHERE name = ? AND brand = ? AND company_id = ?",
                              (name, brand, cid)).fetchone()
            prod_id = prod['id'] if prod else db.execute(
                "INSERT INTO products (name, brand, price, created_at, updated_at, company_id) VALUES (?, ?, ?, ?, ?, ?)",
                (name, brand, 0, now, now, cid)).lastrowid
            inv = db.execute("SELECT id, quantity FROM inventory WHERE product_id = ? AND location_id = ?",
                             (prod_id, loc_id)).fetchone()
            if inv:
                db.execute("UPDATE inventory SET quantity = ?, last_updated = ? WHERE id = ?",
                           (inv['quantity'] + int(qty), now, inv['id']))
            else:
                db.execute(
                    "INSERT INTO inventory (product_id, location_id, quantity, last_updated, company_id) VALUES (?, ?, ?, ?, ?)",
                    (prod_id, loc_id, int(qty), now, cid))
            db.commit();
            return jsonify({'message': 'Inventory updated.'})
        except Exception as e:
            db.rollback(); app.logger.error(f"Add inventory error: {e}"); return jsonify(
                {'error': 'Server error.'}), 500


@app.route('/api/inventory/<int:inventory_id>', methods=['DELETE'])
@api_login_required
@role_required(['admin', 'warehouse'])
@csrf_protect
def delete_inventory_item(inventory_id):
    db = get_db();
    item = db.execute('SELECT id FROM inventory WHERE id = ? AND company_id = ?',
                      (inventory_id, session['company_id'])).fetchone()
    if not item: return jsonify({'error': 'Item not found.'}), 404
    db.execute('DELETE FROM inventory WHERE id = ?', (inventory_id,));
    db.commit();
    return jsonify({'message': 'Item deleted.'})


@app.route('/api/transfers', methods=['GET', 'POST'])
@api_login_required
@csrf_protect
def handle_transfers():
    db = get_db();
    cid = session['company_id']
    if request.method == 'GET':
        page, status, per_page = request.args.get('page', 1, type=int), request.args.get('status', 'all'), 10
        base_q = "SELECT t.*, p.name as product_name, u.username as initiated_by_name, fl.name as from_location_name, tl.name as to_location_name FROM transfers t JOIN products p ON t.product_id = p.id JOIN users u ON t.initiated_by = u.id JOIN locations fl ON t.from_location_id = fl.id JOIN locations tl ON t.to_location_id = tl.id WHERE t.company_id = ?";
        params = [cid]
        if status != 'all': base_q += " AND t.status = ?"; params.append(status)
        total = db.execute(f"SELECT COUNT(*) FROM ({base_q})", params).fetchone()[0]
        items = db.execute(base_q + " ORDER BY t.created_at DESC LIMIT ? OFFSET ?",
                           params + [per_page, (page - 1) * per_page]).fetchall()
        return jsonify({'data': [dict(i) for i in items],
                        'pagination': {'page': page, 'total_pages': (total + per_page - 1) // per_page,
                                       'total': total}})

    if request.method == 'POST':
        data = request.get_json();
        p_id, from_loc, to_loc, qty = data.get('product_id'), data.get('from_location_id'), data.get(
            'to_location_id'), data.get('quantity')
        if not all([p_id, from_loc, to_loc, qty]): return jsonify({'error': 'Missing fields'}), 400
        if from_loc == to_loc: return jsonify({'error': 'Locations cannot be same'}), 400
        try:
            inv = db.execute("SELECT quantity FROM inventory WHERE product_id=? AND location_id=? AND company_id=?",
                             (p_id, from_loc, cid)).fetchone()
            if not inv or inv['quantity'] < int(qty): return jsonify({'error': 'Insufficient stock'}), 400
            now = datetime.now().isoformat()
            db.execute("UPDATE inventory SET quantity = quantity - ? WHERE product_id = ? AND location_id = ?",
                       (qty, p_id, from_loc))
            dest_inv = db.execute("SELECT id FROM inventory WHERE product_id=? AND location_id=?",
                                  (p_id, to_loc)).fetchone()
            if dest_inv:
                db.execute("UPDATE inventory SET quantity = quantity + ? WHERE id = ?", (qty, dest_inv['id']))
            else:
                db.execute(
                    "INSERT INTO inventory (company_id, product_id, location_id, quantity, last_updated) VALUES (?, ?, ?, ?, ?)",
                    (cid, p_id, to_loc, qty, now))
            db.execute(
                "INSERT INTO transfers (company_id, product_id, from_location_id, to_location_id, quantity, status, initiated_by, created_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (cid, p_id, from_loc, to_loc, qty, 'completed', session['user_id'], now, now));
            db.commit()
            return jsonify({'message': 'Transfer successful'}), 201
        except Exception as e:
            db.rollback(); app.logger.error(f"Transfer error: {e}"); return jsonify({'error': 'Server error'}), 500


@app.route('/api/sales', methods=['GET', 'POST'])
@api_login_required
@csrf_protect
def handle_sales():
    db = get_db();
    cid = session['company_id']
    if request.method == 'GET':
        page, loc_id, search, per_page = request.args.get('page', 1, type=int), request.args.get('location_id',
                                                                                                 'all'), request.args.get(
            'search', ''), 10
        base_q = "SELECT s.*, l.name as location_name, u.username as created_by_name, (SELECT COUNT(*) FROM sale_items WHERE sale_id = s.id) as items_count FROM sales s JOIN locations l ON s.location_id = l.id JOIN users u ON s.created_by = u.id WHERE s.company_id = ? AND (s.customer_name LIKE ?)";
        params = [cid, f'%{search}%']
        if loc_id != 'all': base_q += " AND s.location_id = ?"; params.append(loc_id)
        total = db.execute(f"SELECT COUNT(*) FROM ({base_q})", params).fetchone()[0]
        items = db.execute(base_q + " ORDER BY s.created_at DESC LIMIT ? OFFSET ?",
                           params + [per_page, (page - 1) * per_page]).fetchall()
        return jsonify({'data': [dict(i) for i in items],
                        'pagination': {'page': page, 'total_pages': (total + per_page - 1) // per_page,
                                       'total': total}})

    if request.method == 'POST':
        data = request.get_json();
        loc_id, customer, items = data.get('location_id'), data.get('customer_name'), data.get('items')
        if not all([loc_id, items]): return jsonify({'error': 'Missing fields'}), 400
        try:
            total = 0;
            now = datetime.now().isoformat()
            for i in items:
                prod = db.execute("SELECT price FROM products WHERE id=? AND company_id=?",
                                  (i['product_id'], cid)).fetchone()
                if not prod: raise ValueError(f"Prod ID {i['product_id']} not found.")
                inv = db.execute("SELECT quantity FROM inventory WHERE product_id=? AND location_id=?",
                                 (i['product_id'], loc_id)).fetchone()
                if not inv or inv['quantity'] < int(i['quantity']): raise ValueError(
                    f"Insufficient stock for prod ID {i['product_id']}.")
                total += prod['price'] * int(i['quantity'])
            sale_id = db.execute(
                "INSERT INTO sales (company_id, customer_name, location_id, total_amount, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (cid, customer, loc_id, total, session['user_id'], now)).lastrowid
            for i in items:
                price = db.execute("SELECT price FROM products WHERE id=?", (i['product_id'],)).fetchone()['price']
                db.execute(
                    "INSERT INTO sale_items (sale_id, product_id, quantity, unit_price, company_id) VALUES (?, ?, ?, ?, ?)",
                    (sale_id, i['product_id'], i['quantity'], price, cid))
                db.execute("UPDATE inventory SET quantity = quantity - ? WHERE product_id = ? AND location_id = ?",
                           (i['quantity'], i['product_id'], loc_id))
            db.commit();
            return jsonify({'message': 'Sale created!', 'sale_id': sale_id, 'total_amount': total}), 201
        except Exception as e:
            db.rollback(); app.logger.error(f"Sale error: {e}"); return jsonify({'error': str(e)}), 500


@app.route('/api/sales/<int:sale_id>', methods=['GET'])
@api_login_required
def get_sale_details(sale_id):
    db = get_db();
    sale = db.execute(
        "SELECT s.*, l.name as location_name, u.username as created_by_name FROM sales s JOIN locations l ON s.location_id=l.id JOIN users u ON s.created_by=u.id WHERE s.id=? AND s.company_id=?",
        (sale_id, session['company_id'])).fetchone()
    if not sale: return jsonify({'error': 'Sale not found'}), 404
    items = db.execute(
        "SELECT si.*, p.name as product_name, p.brand FROM sale_items si JOIN products p ON si.product_id=p.id WHERE si.sale_id=?",
        (sale_id,)).fetchall()
    return jsonify({'sale': dict(sale), 'items': [dict(i) for i in items]})


@app.route('/api/dashboard/stats', methods=['GET'])
@api_login_required
def get_dashboard_stats():
    db = get_db();
    cid = session['company_id'];
    stats = {}
    stocks = {r['type']: r['total'] for r in db.execute(
        "SELECT l.type, SUM(i.quantity) as total FROM inventory i JOIN locations l ON i.location_id=l.id WHERE i.company_id=? GROUP BY l.type",
        (cid,)).fetchall()}
    stats['warehouse_stock'], stats['showroom_stock'], stats['project_site_stock'] = stocks.get('warehouse',
                                                                                                0), stocks.get(
        'showroom', 0), stocks.get('project', 0)
    stats['total_inventory'] = sum(stocks.values())
    stats['pending_transfers'] = \
    db.execute("SELECT COUNT(*) FROM transfers WHERE company_id=? AND status='pending'", (cid,)).fetchone()[0]
    stats['recent_activity'] = [dict(r) for r in db.execute(
        "SELECT t.*, p.name as product_name, u.username as initiated_by_name, fl.name as from_location, tl.name as to_location FROM transfers t JOIN products p ON t.product_id=p.id JOIN users u ON t.initiated_by=u.id JOIN locations fl ON t.from_location_id=fl.id JOIN locations tl ON t.to_location_id=tl.id WHERE t.company_id=? ORDER BY t.created_at DESC LIMIT 5",
        (cid,)).fetchall()]
    return jsonify(stats)


@app.route('/api/reports', methods=['GET'])
@api_login_required
@role_required(['admin'])
def get_reports():
    db = get_db();
    cid = session['company_id'];
    args = request.args;
    r_type, start, end = args.get('type'), args.get('start_date'), args.get('end_date')
    if not all([r_type, start, end]): return jsonify({'error': 'Missing parameters'}), 400
    end = end + ' 23:59:59'

    if r_type == 'sales':
        query = "SELECT s.created_at as Date, l.name as Location, p.name as Product, si.quantity as Quantity, si.unit_price as 'Unit_Price', (si.quantity * si.unit_price) as Total FROM sales s JOIN sale_items si ON s.id = si.sale_id JOIN products p ON si.product_id = p.id JOIN locations l ON s.location_id = l.id WHERE s.company_id = ? AND s.created_at BETWEEN ? AND ? ORDER BY s.created_at DESC"
        data = db.execute(query, (cid, start, end)).fetchall()
        return jsonify([dict(row) for row in data])
    elif r_type == 'transfers':
        query = "SELECT t.created_at as Date, p.name as Product, t.quantity as Quantity, fl.name as 'From', tl.name as 'To', u.username as 'By' FROM transfers t JOIN products p ON t.product_id = p.id JOIN locations fl ON t.from_location_id = fl.id JOIN locations tl ON t.to_location_id = tl.id JOIN users u ON t.initiated_by = u.id WHERE t.company_id = ? AND t.created_at BETWEEN ? AND ? ORDER BY t.created_at DESC"
        data = db.execute(query, (cid, start, end)).fetchall()
        return jsonify([dict(row) for row in data])

    return jsonify({'error': 'Invalid report type'}), 400


# ==============================================================================
# HTML ROUTES & MAIN
# ==============================================================================
@app.route('/')
def index(): return render_template('index.html') if 'user_id' in session else redirect(url_for('login'))


@app.route('/login')
def login(): return render_template('login.html')


@app.route('/register')
def register(): return render_template('register.html')


if __name__ == '__main__':
    if not os.path.exists(app.config['DATABASE']): init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)