import os
import sqlite3
import secrets
import csv
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, g, render_template, redirect, url_for, session, make_response

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Strong secret key
app.config['DATABASE'] = 'erp.db'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Database setup with connection pooling
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
        # Enable foreign key constraints
        db.execute('PRAGMA foreign_keys = ON')
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # Create tables with proper constraints
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'warehouse', 'showroom')),
                created_at TEXT NOT NULL,
                last_login TEXT,
                is_active INTEGER DEFAULT 1
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                brand TEXT NOT NULL,
                description TEXT,
                price REAL NOT NULL CHECK(price >= 0),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER NOT NULL,
                location TEXT NOT NULL CHECK(location IN ('warehouse', 'showroom')),
                quantity INTEGER NOT NULL CHECK(quantity >= 0),
                last_updated TEXT NOT NULL,
                FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE,
                UNIQUE(product_id, location)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER NOT NULL,
                from_location TEXT NOT NULL CHECK(from_location IN ('warehouse', 'showroom')),
                to_location TEXT NOT NULL CHECK(to_location IN ('warehouse', 'showroom', 'customer')),
                quantity INTEGER NOT NULL CHECK(quantity > 0),
                status TEXT NOT NULL CHECK(status IN ('pending', 'completed', 'cancelled')),
                initiated_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE,
                FOREIGN KEY (initiated_by) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_name TEXT,
                location TEXT NOT NULL CHECK(location IN ('warehouse', 'showroom')),
                total_amount REAL NOT NULL CHECK(total_amount >= 0),
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sale_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sale_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL CHECK(quantity > 0),
                unit_price REAL NOT NULL CHECK(unit_price >= 0),
                FOREIGN KEY (sale_id) REFERENCES sales (id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE
            )
        ''')

        # Create audit log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                table_name TEXT,
                record_id INTEGER,
                old_values TEXT,
                new_values TEXT,
                ip_address TEXT,
                user_agent TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            )
        ''')

        # Create initial admin user if they don't exist
        default_users = [
            ('admin', 'Admin@123', 'admin'),
            ('warehouse', 'Warehouse@123', 'warehouse'),
            ('showroom', 'Showroom@123', 'showroom')
        ]

        for username, password, role in default_users:
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            if not cursor.fetchone():
                hashed_password = generate_password_hash(password)
                cursor.execute(
                    'INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)',
                    (username, hashed_password, role, datetime.now().isoformat())
                )

        # Create sample products if none exist
        cursor.execute('SELECT id FROM products LIMIT 1')
        if not cursor.fetchone():
            sample_products = [
                ('Dr. Fixit LW+', 'Dr. Fixit', 'Liquid waterproofing compound', 1200),
                ('Pidilite Fevicol', 'Pidilite', 'Synthetic resin adhesive', 150),
                ('Asian Paints Primer', 'Asian Paints', 'Wall primer', 800),
                ('Berger Weathercoat', 'Berger', 'Exterior wall paint', 950)
            ]

            for name, brand, description, price in sample_products:
                now = datetime.now().isoformat()
                cursor.execute(
                    'INSERT INTO products (name, brand, description, price, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
                    (name, brand, description, price, now, now)
                )

            # Add initial inventory
            cursor.execute('SELECT id FROM products')
            product_ids = [row[0] for row in cursor.fetchall()]
            for product_id in product_ids:
                for location in ['warehouse', 'showroom']:
                    quantity = 100 if location == 'warehouse' else 20
                    cursor.execute(
                        'INSERT INTO inventory (product_id, location, quantity, last_updated) VALUES (?, ?, ?, ?)',
                        (product_id, location, quantity, datetime.now().isoformat())
                    )

        db.commit()

# Security decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Authentication required'}), 401
            if session.get('user_role') not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            csrf_token = request.headers.get('X-CSRF-Token')
            if not csrf_token or csrf_token != session.get('csrf_token'):
                return jsonify({'error': 'Invalid CSRF token'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Audit logging function
def log_audit(action, table_name=None, record_id=None, old_values=None, new_values=None):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            '''INSERT INTO audit_log 
            (user_id, action, table_name, record_id, old_values, new_values, ip_address, user_agent, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                session.get('user_id'),
                action,
                table_name,
                record_id,
                str(old_values) if old_values else None,
                str(new_values) if new_values else None,
                request.remote_addr,
                request.headers.get('User-Agent'),
                datetime.now().isoformat()
            )
        )
        db.commit()
    except Exception as e:
        app.logger.error(f"Failed to log audit: {str(e)}")

# API Endpoints
@app.route('/api/csrf-token', methods=['GET'])
@login_required
def get_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return jsonify({'csrf_token': session['csrf_token']})

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if 'user_id' in session:
        return jsonify({
            'authenticated': True,
            'user': {
                'id': session['user_id'],
                'username': session['username'],
                'role': session['user_role']
            }
        }), 200
    return jsonify({'authenticated': False}), 200

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400

    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    if not username or not password or not role:
        return jsonify({'error': 'Missing credentials'}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,))
        user = cursor.fetchone()

        if not user or not check_password_hash(user['password'], password):
            log_audit('login_failed', None, None, None, {'username': username})
            return jsonify({'error': 'Invalid credentials'}), 401

        if user['role'] != role:
            log_audit('login_failed_role', None, None, None, {'username': username, 'attempted_role': role})
            return jsonify({'error': 'User does not have the selected role'}), 403

        # Update last login
        cursor.execute('UPDATE users SET last_login = ? WHERE id = ?',
                       (datetime.now().isoformat(), user['id']))
        db.commit()

        # Setup session
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['user_role'] = user['role']
        session['csrf_token'] = secrets.token_hex(16)  # Generate CSRF token

        log_audit('login_success', 'users', user['id'])

        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role']
            },
            'csrf_token': session['csrf_token']
        })
    except Exception as e:
        db.rollback()
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/logout', methods=['POST'])
@login_required
@csrf_protect
def api_logout():
    log_audit('logout', 'users', session['user_id'])
    session.clear()
    return jsonify({'message': 'Logout successful'})

@app.route('/api/inventory', methods=['GET'])
@login_required
def get_inventory():
    location = request.args.get('location', 'all')
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    try:
        db = get_db()
        cursor = db.cursor()

        base_query = '''
            SELECT i.id, p.id as product_id, p.name, p.brand, i.location, i.quantity, i.last_updated 
            FROM inventory i
            JOIN products p ON i.product_id = p.id
            WHERE (p.name LIKE ? OR p.brand LIKE ?)
        '''
        params = [f'%{search}%', f'%{search}%']

        if location != 'all':
            base_query += ' AND i.location = ?'
            params.append(location)

        # Count total items for pagination
        count_query = f"SELECT COUNT(*) as total FROM ({base_query})"
        cursor.execute(count_query, params)
        total_items = cursor.fetchone()['total']

        # Add pagination
        query = base_query + ' ORDER BY p.name LIMIT ? OFFSET ?'
        params.extend([per_page, (page - 1) * per_page])

        cursor.execute(query, params)
        inventory = [dict(row) for row in cursor.fetchall()]

        return jsonify({
            'data': inventory,
            'pagination': {
                'total': total_items,
                'page': page,
                'per_page': per_page,
                'total_pages': (total_items + per_page - 1) // per_page
            }
        })
    except Exception as e:
        app.logger.error(f"Error fetching inventory: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/inventory/<int:inventory_id>', methods=['DELETE'])
@login_required
@role_required(['admin', 'warehouse'])
@csrf_protect
def delete_inventory(inventory_id):
    db = get_db()
    cursor = db.cursor()

    try:
        # Get inventory details before deletion for audit log
        cursor.execute('SELECT * FROM inventory WHERE id = ?', (inventory_id,))
        inventory = cursor.fetchone()
        if not inventory:
            return jsonify({'error': 'Inventory item not found'}), 404

        cursor.execute('DELETE FROM inventory WHERE id = ?', (inventory_id,))
        db.commit()

        log_audit('delete', 'inventory', inventory_id, dict(inventory))
        return jsonify({'message': 'Inventory item deleted successfully'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error deleting inventory: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/inventory', methods=['POST'])
@login_required
@role_required(['admin', 'warehouse'])
@csrf_protect
def add_inventory():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400

    name = data.get('name')
    brand = data.get('brand')
    location = data.get('location')
    quantity = data.get('quantity')

    if not all([name, brand, location, quantity]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        quantity = int(quantity)
        if quantity <= 0:
            return jsonify({'error': 'Quantity must be positive'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid quantity'}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        # Check if product exists
        cursor.execute('SELECT id FROM products WHERE name = ? AND brand = ?', (name, brand))
        product = cursor.fetchone()

        if not product:
            # Create new product with default price
            now = datetime.now().isoformat()
            cursor.execute('''
                INSERT INTO products (name, brand, description, price, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (name, brand, '', 0, now, now))
            product_id = cursor.lastrowid
            log_audit('create', 'products', product_id, None, {'name': name, 'brand': brand})
        else:
            product_id = product['id']

        # Check if inventory exists for this product and location
        cursor.execute('''
            SELECT id, quantity FROM inventory 
            WHERE product_id = ? AND location = ?
        ''', (product_id, location))
        existing = cursor.fetchone()

        if existing:
            # Update existing inventory
            new_quantity = existing['quantity'] + quantity
            cursor.execute('''
                UPDATE inventory 
                SET quantity = ?, last_updated = ?
                WHERE id = ?
            ''', (new_quantity, datetime.now().isoformat(), existing['id']))
            log_audit('update', 'inventory', existing['id'],
                      {'quantity': existing['quantity']}, {'quantity': new_quantity})
        else:
            # Create new inventory record
            cursor.execute('''
                INSERT INTO inventory (product_id, location, quantity, last_updated)
                VALUES (?, ?, ?, ?)
            ''', (product_id, location, quantity, datetime.now().isoformat()))
            inventory_id = cursor.lastrowid
            log_audit('create', 'inventory', inventory_id, None,
                      {'product_id': product_id, 'location': location, 'quantity': quantity})

        db.commit()
        return jsonify({'message': 'Inventory updated successfully'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error adding inventory: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/transfers', methods=['GET'])
@login_required
def get_transfers():
    status = request.args.get('status', 'all')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    try:
        db = get_db()
        cursor = db.cursor()

        base_query = '''
            SELECT t.*, p.name as product_name, u.username as initiated_by_name
            FROM transfers t
            JOIN products p ON t.product_id = p.id
            JOIN users u ON t.initiated_by = u.id
        '''
        params = []

        if status != 'all':
            base_query += ' WHERE t.status = ?'
            params.append(status)

        # Count total items for pagination
        count_query = f"SELECT COUNT(*) as total FROM ({base_query})"
        cursor.execute(count_query, params)
        total_items = cursor.fetchone()['total']

        # Add pagination
        query = base_query + ' ORDER BY t.created_at DESC LIMIT ? OFFSET ?'
        params.extend([per_page, (page - 1) * per_page])

        cursor.execute(query, params)
        transfers = [dict(row) for row in cursor.fetchall()]

        return jsonify({
            'data': transfers,
            'pagination': {
                'total': total_items,
                'page': page,
                'per_page': per_page,
                'total_pages': (total_items + per_page - 1) // per_page
            }
        })
    except Exception as e:
        app.logger.error(f"Error fetching transfers: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/transfers/<int:transfer_id>', methods=['GET'])
@login_required
def get_transfer_details(transfer_id):
    try:
        db = get_db()
        cursor = db.cursor()

        cursor.execute('''
            SELECT t.*, p.name as product_name, u.username as initiated_by_name
            FROM transfers t
            JOIN products p ON t.product_id = p.id
            JOIN users u ON t.initiated_by = u.id
            WHERE t.id = ?
        ''', (transfer_id,))
        transfer = cursor.fetchone()

        if not transfer:
            return jsonify({'error': 'Transfer not found'}), 404

        return jsonify(dict(transfer))
    except Exception as e:
        app.logger.error(f"Error fetching transfer details: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/transfers', methods=['POST'])
@login_required
@role_required(['admin', 'warehouse', 'showroom'])
@csrf_protect
def create_transfer():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400

    product_id = data.get('product_id')
    from_location = data.get('from_location')
    to_location = data.get('to_location')
    quantity = data.get('quantity')

    if not all([product_id, from_location, to_location, quantity]):
        return jsonify({'error': 'Missing required fields'}), 400

    if from_location == to_location:
        return jsonify({'error': 'Source and destination cannot be the same'}), 400

    try:
        quantity = int(quantity)
        if quantity <= 0:
            return jsonify({'error': 'Quantity must be positive'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid quantity'}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        # Check if source has enough inventory
        cursor.execute('''
            SELECT quantity FROM inventory
            WHERE product_id = ? AND location = ?
        ''', (product_id, from_location))
        source_inventory = cursor.fetchone()

        if not source_inventory or source_inventory['quantity'] < quantity:
            return jsonify({'error': 'Insufficient inventory at source location'}), 400

        # Create transfer record
        cursor.execute('''
            INSERT INTO transfers (
                product_id, from_location, to_location, quantity, 
                status, initiated_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            product_id, from_location, to_location, quantity,
            'pending', session['user_id'], datetime.now().isoformat()
        ))

        transfer_id = cursor.lastrowid
        log_audit('create', 'transfers', transfer_id, None, {
            'product_id': product_id,
            'from_location': from_location,
            'to_location': to_location,
            'quantity': quantity,
            'status': 'pending'
        })

        # For immediate transfers (not pending), process the transfer
        if to_location != 'customer':
            # Reduce source inventory
            cursor.execute('''
                UPDATE inventory
                SET quantity = quantity - ?, last_updated = ?
                WHERE product_id = ? AND location = ?
            ''', (quantity, datetime.now().isoformat(), product_id, from_location))

            # Check if destination inventory exists
            cursor.execute('''
                SELECT quantity FROM inventory
                WHERE product_id = ? AND location = ?
            ''', (product_id, to_location))
            dest_inventory = cursor.fetchone()

            if dest_inventory:
                # Update existing inventory
                cursor.execute('''
                    UPDATE inventory
                    SET quantity = quantity + ?, last_updated = ?
                    WHERE product_id = ? AND location = ?
                ''', (quantity, datetime.now().isoformat(), product_id, to_location))
            else:
                # Create new inventory record
                cursor.execute('''
                    INSERT INTO inventory (
                        product_id, location, quantity, last_updated
                    ) VALUES (?, ?, ?, ?)
                ''', (product_id, to_location, quantity, datetime.now().isoformat()))

            # Mark transfer as completed
            cursor.execute('''
                UPDATE transfers
                SET status = 'completed', completed_at = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), transfer_id))

            log_audit('update', 'transfers', transfer_id, {'status': 'pending'}, {'status': 'completed'})

        db.commit()
        return jsonify({
            'message': 'Transfer created successfully',
            'transfer_id': transfer_id
        })
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error creating transfer: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/transfers/<int:transfer_id>/complete', methods=['POST'])
@login_required
@role_required(['admin', 'warehouse'])
@csrf_protect
def complete_transfer(transfer_id):
    db = get_db()
    cursor = db.cursor()

    try:
        # Get transfer details
        cursor.execute('''
            SELECT * FROM transfers
            WHERE id = ? AND status = 'pending'
        ''', (transfer_id,))
        transfer = cursor.fetchone()

        if not transfer:
            return jsonify({'error': 'Transfer not found or already completed'}), 404

        # Check if source has enough inventory
        cursor.execute('''
            SELECT quantity FROM inventory
            WHERE product_id = ? AND location = ?
        ''', (transfer['product_id'], transfer['from_location']))
        source_inventory = cursor.fetchone()

        if not source_inventory or source_inventory['quantity'] < transfer['quantity']:
            return jsonify({'error': 'Insufficient inventory at source location'}), 400

        # Process the transfer
        # Reduce source inventory
        cursor.execute('''
            UPDATE inventory
            SET quantity = quantity - ?, last_updated = ?
            WHERE product_id = ? AND location = ?
        ''', (transfer['quantity'], datetime.now().isoformat(),
              transfer['product_id'], transfer['from_location']))

        # Check if destination inventory exists
        cursor.execute('''
            SELECT quantity FROM inventory
            WHERE product_id = ? AND location = ?
        ''', (transfer['product_id'], transfer['to_location']))
        dest_inventory = cursor.fetchone()

        if dest_inventory:
            # Update existing inventory
            cursor.execute('''
                UPDATE inventory
                SET quantity = quantity + ?, last_updated = ?
                WHERE product_id = ? AND location = ?
            ''', (transfer['quantity'], datetime.now().isoformat(),
                  transfer['product_id'], transfer['to_location']))
        else:
            # Create new inventory record
            cursor.execute('''
                INSERT INTO inventory (
                    product_id, location, quantity, last_updated
                ) VALUES (?, ?, ?, ?)
            ''', (transfer['product_id'], transfer['to_location'],
                  transfer['quantity'], datetime.now().isoformat()))

        # Mark transfer as completed
        cursor.execute('''
            UPDATE transfers
            SET status = 'completed', completed_at = ?
            WHERE id = ?
        ''', (datetime.now().isoformat(), transfer_id))

        log_audit('update', 'transfers', transfer_id, {'status': 'pending'}, {'status': 'completed'})
        db.commit()
        return jsonify({'message': 'Transfer completed successfully'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error completing transfer: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/sales', methods=['GET'])
@login_required
def get_sales():
    location = request.args.get('location', 'all')
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    try:
        db = get_db()
        cursor = db.cursor()

        base_query = '''
            SELECT s.*, u.username as created_by_name,
                   (SELECT COUNT(*) FROM sale_items WHERE sale_id = s.id) as items_count
            FROM sales s
            JOIN users u ON s.created_by = u.id
            WHERE (s.customer_name LIKE ? OR u.username LIKE ?)
        '''
        params = [f'%{search}%', f'%{search}%']

        if location != 'all':
            base_query += ' AND s.location = ?'
            params.append(location)

        # Count total items for pagination
        count_query = f"SELECT COUNT(*) as total FROM ({base_query})"
        cursor.execute(count_query, params)
        total_items = cursor.fetchone()['total']

        # Add pagination
        query = base_query + ' ORDER BY s.created_at DESC LIMIT ? OFFSET ?'
        params.extend([per_page, (page - 1) * per_page])

        cursor.execute(query, params)
        sales = [dict(row) for row in cursor.fetchall()]

        return jsonify({
            'data': sales,
            'pagination': {
                'total': total_items,
                'page': page,
                'per_page': per_page,
                'total_pages': (total_items + per_page - 1) // per_page
            }
        })
    except Exception as e:
        app.logger.error(f"Error fetching sales: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/sales/<int:sale_id>', methods=['GET'])
@login_required
def get_sale_details(sale_id):
    try:
        db = get_db()
        cursor = db.cursor()

        # Get sale details
        cursor.execute('''
            SELECT s.*, u.username as created_by_name
            FROM sales s
            JOIN users u ON s.created_by = u.id
            WHERE s.id = ?
        ''', (sale_id,))
        sale = cursor.fetchone()

        if not sale:
            return jsonify({'error': 'Sale not found'}), 404

        # Get sale items
        cursor.execute('''
            SELECT si.*, p.name as product_name, p.brand
            FROM sale_items si
            JOIN products p ON si.product_id = p.id
            WHERE si.sale_id = ?
        ''', (sale_id,))
        items = [dict(row) for row in cursor.fetchall()]

        return jsonify({
            'sale': dict(sale),
            'items': items
        })
    except Exception as e:
        app.logger.error(f"Error fetching sale details: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/sales/<int:sale_id>/items', methods=['GET'])
@login_required
def get_sale_items(sale_id):
    try:
        db = get_db()
        cursor = db.cursor()

        cursor.execute('''
            SELECT si.*, p.name as product_name, p.brand
            FROM sale_items si
            JOIN products p ON si.product_id = p.id
            WHERE si.sale_id = ?
        ''', (sale_id,))
        items = [dict(row) for row in cursor.fetchall()]

        return jsonify(items)
    except Exception as e:
        app.logger.error(f"Error fetching sale items: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/sales', methods=['POST'])
@login_required
@role_required(['admin', 'showroom', 'warehouse'])
@csrf_protect
def create_sale():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400

    customer_name = data.get('customer_name', '')
    location = data.get('location')
    items = data.get('items')

    if not location or not items:
        return jsonify({'error': 'Missing required fields'}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        # Calculate total amount and validate items
        total_amount = 0
        for item in items:
            try:
                product_id = int(item['product_id'])
                quantity = int(item['quantity'])

                if quantity <= 0:
                    return jsonify({'error': 'Quantity must be positive'}), 400

                # Get product price
                cursor.execute('SELECT price FROM products WHERE id = ?', (product_id,))
                product = cursor.fetchone()
                if not product:
                    return jsonify({'error': f'Product with ID {product_id} not found'}), 404

                price = product['price']

                # Check inventory
                cursor.execute('''
                    SELECT quantity FROM inventory
                    WHERE product_id = ? AND location = ?
                ''', (product_id, location))
                inventory = cursor.fetchone()

                if not inventory or inventory['quantity'] < quantity:
                    return jsonify({'error': f'Insufficient inventory for product ID {product_id}'}), 400

                total_amount += price * quantity

            except (KeyError, ValueError):
                return jsonify({'error': 'Invalid item data'}), 400

        # Create sale record
        cursor.execute('''
            INSERT INTO sales (
                customer_name, location, total_amount, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?)
        ''', (customer_name, location, total_amount, session['user_id'], datetime.now().isoformat()))

        sale_id = cursor.lastrowid
        log_audit('create', 'sales', sale_id, None, {
            'customer_name': customer_name,
            'location': location,
            'total_amount': total_amount
        })

        # Create sale items and update inventory
        for item in items:
            product_id = int(item['product_id'])
            quantity = int(item['quantity'])

            # Get product price
            cursor.execute('SELECT price FROM products WHERE id = ?', (product_id,))
            product = cursor.fetchone()
            price = product['price']

            cursor.execute('''
                INSERT INTO sale_items (
                    sale_id, product_id, quantity, unit_price
                ) VALUES (?, ?, ?, ?)
            ''', (sale_id, product_id, quantity, price))

            log_audit('create', 'sale_items', cursor.lastrowid, None, {
                'sale_id': sale_id,
                'product_id': product_id,
                'quantity': quantity,
                'unit_price': price
            })

            # Reduce inventory
            cursor.execute('''
                UPDATE inventory
                SET quantity = quantity - ?, last_updated = ?
                WHERE product_id = ? AND location = ?
            ''', (quantity, datetime.now().isoformat(), product_id, location))

            log_audit('update', 'inventory', None, None, {
                'product_id': product_id,
                'location': location,
                'quantity_change': -quantity
            })

        db.commit()
        return jsonify({
            'message': 'Sale created successfully',
            'sale_id': sale_id,
            'total_amount': total_amount
        })
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error creating sale: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/products', methods=['GET'])
@login_required
def get_products():
    try:
        db = get_db()
        cursor = db.cursor()

        cursor.execute('''
            SELECT p.*, 
                   (SELECT SUM(quantity) FROM inventory WHERE product_id = p.id AND location = 'warehouse') as warehouse_stock,
                   (SELECT SUM(quantity) FROM inventory WHERE product_id = p.id AND location = 'showroom') as showroom_stock
            FROM products p
            ORDER BY p.name
        ''')

        products = [dict(row) for row in cursor.fetchall()]
        return jsonify(products)
    except Exception as e:
        app.logger.error(f"Error fetching products: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/dashboard/stats', methods=['GET'])
@login_required
def get_dashboard_stats():
    try:
        db = get_db()
        cursor = db.cursor()

        # Total inventory
        cursor.execute('SELECT SUM(quantity) as total FROM inventory')
        total_inventory = cursor.fetchone()['total'] or 0

        # Warehouse stock
        cursor.execute('SELECT SUM(quantity) as total FROM inventory WHERE location = "warehouse"')
        warehouse_stock = cursor.fetchone()['total'] or 0

        # Showroom stock
        cursor.execute('SELECT SUM(quantity) as total FROM inventory WHERE location = "showroom"')
        showroom_stock = cursor.fetchone()['total'] or 0

        # Pending transfers
        cursor.execute('SELECT COUNT(*) as total FROM transfers WHERE status = "pending"')
        pending_transfers = cursor.fetchone()['total'] or 0

        # Recent activity (transfers)
        cursor.execute('''
            SELECT t.*, p.name as product_name, u.username as initiated_by_name
            FROM transfers t
            JOIN products p ON t.product_id = p.id
            JOIN users u ON t.initiated_by = u.id
            ORDER BY t.created_at DESC
            LIMIT 5
        ''')
        recent_activity = [dict(row) for row in cursor.fetchall()]

        return jsonify({
            'total_inventory': total_inventory,
            'warehouse_stock': warehouse_stock,
            'showroom_stock': showroom_stock,
            'pending_transfers': pending_transfers,
            'recent_activity': recent_activity
        })
    except Exception as e:
        app.logger.error(f"Error fetching dashboard stats: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/dashboard/charts/inventory', methods=['GET'])
@login_required
def get_inventory_chart_data():
    days = int(request.args.get('days', 7))

    try:
        db = get_db()
        cursor = db.cursor()

        # Generate date labels
        labels = []
        today = datetime.now().date()
        for i in range(days - 1, -1, -1):
            date = today - timedelta(days=i)
            labels.append(date.strftime('%b %d'))

        # Get received data (incoming transfers)
        received_data = []
        for i in range(days):
            date = today - timedelta(days=i)
            cursor.execute('''
                SELECT SUM(quantity) as total FROM transfers 
                WHERE to_location IN ('warehouse', 'showroom') 
                AND status = 'completed'
                AND date(created_at) = ?
            ''', (date.isoformat(),))
            result = cursor.fetchone()
            received_data.append(result['total'] or 0)

        # Get transferred data (outgoing transfers)
        transferred_data = []
        for i in range(days):
            date = today - timedelta(days=i)
            cursor.execute('''
                SELECT SUM(quantity) as total FROM transfers 
                WHERE from_location IN ('warehouse', 'showroom') 
                AND status = 'completed'
                AND date(created_at) = ?
            ''', (date.isoformat(),))
            result = cursor.fetchone()
            transferred_data.append(result['total'] or 0)

        return jsonify({
            'labels': labels,
            'received': received_data,
            'transferred': transferred_data
        })
    except Exception as e:
        app.logger.error(f"Error fetching inventory chart data: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/dashboard/charts/sales', methods=['GET'])
@login_required
def get_sales_chart_data():
    days = int(request.args.get('days', 7))

    try:
        db = get_db()
        cursor = db.cursor()

        # Generate date labels
        labels = []
        today = datetime.now().date()
        for i in range(days - 1, -1, -1):
            date = today - timedelta(days=i)
            labels.append(date.strftime('%b %d'))

        # Get warehouse sales
        warehouse_sales = []
        for i in range(days):
            date = today - timedelta(days=i)
            cursor.execute('''
                SELECT SUM(total_amount) as total FROM sales 
                WHERE location = 'warehouse'
                AND date(created_at) = ?
            ''', (date.isoformat(),))
            result = cursor.fetchone()
            warehouse_sales.append(result['total'] or 0)

        # Get showroom sales
        showroom_sales = []
        for i in range(days):
            date = today - timedelta(days=i)
            cursor.execute('''
                SELECT SUM(total_amount) as total FROM sales 
                WHERE location = 'showroom'
                AND date(created_at) = ?
            ''', (date.isoformat(),))
            result = cursor.fetchone()
            showroom_sales.append(result['total'] or 0)

        return jsonify({
            'labels': labels,
            'warehouse_sales': warehouse_sales,
            'showroom_sales': showroom_sales
        })
    except Exception as e:
        app.logger.error(f"Error fetching sales chart data: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# HTML Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    if not os.path.exists(app.config['DATABASE']):
        init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)