import os
import sqlite3
import uuid
import re
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, send_from_directory, abort
from markupsafe import escape
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect
from functools import wraps
import html

# 앱 초기화 및 기본 설정
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secret!')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.permanent_session_lifetime = timedelta(minutes=30)

# 보안 모듈 초기화
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
socketio = SocketIO(app)

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log'
)
logger = logging.getLogger('market_app')

# -----------------------------
# 파일 업로드 관련 설정
# -----------------------------
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'upload')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB 제한
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# 업로드 폴더가 없으면 생성
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# -----------------------------
# 데이터베이스 설정
# -----------------------------
DATABASE = 'market.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 파라미터화된 쿼리를 사용하도록 래퍼 함수
def query_db(query, args=(), one=False):
    try:
        cur = get_db().execute(query, args)
        rv = cur.fetchall()
        cur.close()
        return (rv[0] if rv else None) if one else rv
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        get_db().rollback()
        raise

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_blocked INTEGER DEFAULT 0,
                suspended_until TEXT,
                login_attempts INTEGER DEFAULT 0,
                last_login_attempt TEXT
            )
        """)

        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                image TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending'
            )
        """)

        # 지갑 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wallet (
                user_id TEXT PRIMARY KEY,
                balance INTEGER NOT NULL DEFAULT 0
            )
        """)

        # 거래 내역 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 로그 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_log (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 관리자 계정 생성 (admin / admin)
        cursor.execute("SELECT * FROM user WHERE username = 'admin'")
        if cursor.fetchone() is None:
            admin_id = str(uuid.uuid4())
            hashed_pw = bcrypt.generate_password_hash('admin').decode('utf-8')
            cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                           (admin_id, 'admin', hashed_pw))
            cursor.execute("INSERT INTO wallet (user_id, balance) VALUES (?, ?)", (admin_id, 100000))
            logger.info("[INFO] 관리자 계정(admin) 자동 생성 완료")

        db.commit()

# -----------------------------
# 보안 및 인증 관련 함수
# -----------------------------

# XSS 방지를 위한 HTML 이스케이프 함수
def escape_html(text):
    if text is None:
        return None
    return html.escape(text)

# 로그인 필요 데코레이터
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# 관리자 권한 확인 데코레이터
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login', next=request.url))
        
        if session.get('username') != 'admin':
            flash('관리자 권한이 필요합니다.')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

# 사용자 활동 로깅 함수
def log_activity(user_id, action, details=None):
    try:
        db = get_db()
        log_id = str(uuid.uuid4())
        ip_address = request.remote_addr
        
        db.execute(
            "INSERT INTO activity_log (id, user_id, action, details, ip_address) VALUES (?, ?, ?, ?, ?)",
            (log_id, user_id, action, details, ip_address)
        )
        db.commit()
    except Exception as e:
        logger.error(f"로깅 에러: {e}")

# 로그인 시도 제한 확인
def check_login_attempts(username):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT login_attempts, last_login_attempt FROM user WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        return True
    
    attempts = user['login_attempts']
    last_attempt = user['last_login_attempt']
    
    # 5회 이상 실패 시 30분 동안 잠금
    if attempts >= 5:
        if last_attempt:
            try:
                last_time = datetime.strptime(last_attempt, "%Y-%m-%d %H:%M:%S")
                if datetime.now() - last_time < timedelta(minutes=30):
                    return False
                else:
                    # 30분 지나면 초기화
                    cursor.execute("UPDATE user SET login_attempts = 0 WHERE username = ?", (username,))
                    db.commit()
            except ValueError:
                pass
    
    return True

# 로그인 시도 횟수 증가
def increment_login_attempts(username):
    db = get_db()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        "UPDATE user SET login_attempts = login_attempts + 1, last_login_attempt = ? WHERE username = ?",
        (now, username)
    )
    db.commit()

# 로그인 시도 초기화
def reset_login_attempts(username):
    db = get_db()
    db.execute("UPDATE user SET login_attempts = 0 WHERE username = ?", (username,))
    db.commit()

# -----------------------------
# 보안 헤더 설정
# -----------------------------
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

# -----------------------------
# 에러 핸들러
# -----------------------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error='404 - 페이지를 찾을 수 없습니다.'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', error='403 - 접근 권한이 없습니다.'), 403

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"서버 에러: {e}")
    return render_template('error.html', error='500 - 서버 에러가 발생했습니다.'), 500

@app.errorhandler(413)
def request_entity_too_large(e):
    return render_template('error.html', error='413 - 파일 크기가 너무 큽니다.'), 413

# -----------------------------
# 라우트 설정
# -----------------------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # 입력값 검증
        if not (3 <= len(username) <= 20):
            flash('사용자명은 3~20자여야 합니다.')
            return redirect(url_for('register'))
        
        if not (8 <= len(password) <= 50):
            flash('비밀번호는 8자 이상이어야 합니다.')
            return redirect(url_for('register'))
            
        # 영문자, 숫자, 특수문자 포함 여부 검증
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', password):
            flash('비밀번호는 영문자, 숫자, 특수문자를 포함해야 합니다.')
            return redirect(url_for('register'))
        
        # 사용자명 유효성 검증 (알파벳, 숫자, 밑줄만 허용)
        if not re.match(r'^[A-Za-z0-9_]+$', username):
            flash('사용자명은 알파벳, 숫자, 밑줄만 사용할 수 있습니다.')
            return redirect(url_for('register'))
        
        try:
            db = get_db()
            cursor = db.cursor()
            
            # 중복 사용자 체크
            cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
            if cursor.fetchone() is not None:
                flash('이미 존재하는 사용자명입니다.')
                return redirect(url_for('register'))
            
            user_id = str(uuid.uuid4())
            hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
            
            cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                          (user_id, username, hashed_pw))
            cursor.execute("INSERT INTO wallet (user_id, balance) VALUES (?, ?)", (user_id, 10000))
            db.commit()
            
            # 활동 로깅
            log_activity(user_id, "register", f"New user registered: {username}")
            
            flash('회원가입이 완료되었습니다. 로그인 해주세요.')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"회원가입 에러: {e}")
            db.rollback()
            flash('회원가입 처리 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # 로그인 시도 제한 확인
        if not check_login_attempts(username):
            flash('로그인 시도가 너무 많습니다. 30분 후에 다시 시도해주세요.')
            return redirect(url_for('login'))
        
        try:
            db = get_db()
            cursor = db.cursor()
            
            # 사용자 조회
            cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
            user = cursor.fetchone()
            
            if user and bcrypt.check_password_hash(user['password'], password):
                # 차단 여부 확인
                if user['is_blocked']:
                    suspended_until = user['suspended_until']
                    if suspended_until:
                        try:
                            until_date = datetime.strptime(suspended_until, "%Y-%m-%d")
                            if until_date > datetime.now():
                                flash(f"이 계정은 {suspended_until}까지 정지 상태입니다.")
                                return redirect(url_for('login'))
                            else:
                                # 정지 기간 만료 → 자동 해제
                                cursor.execute("UPDATE user SET is_blocked = 0, suspended_until = NULL WHERE id = ?", (user['id'],))
                                db.commit()
                        except ValueError:
                            pass
                
                # 로그인 성공 처리
                session.permanent = True
                session['user_id'] = user['id']
                session['username'] = user['username']
                
                # 로그인 시도 초기화
                reset_login_attempts(username)
                
                # 활동 로깅
                log_activity(user['id'], "login", f"User logged in: {username}")
                
                flash('로그인 성공!')
                
                # next 파라미터가 있으면 해당 페이지로 리다이렉트
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                
                return redirect(url_for('dashboard'))
            else:
                # 로그인 실패 처리
                increment_login_attempts(username)
                
                # 일반적인 오류 메시지 (구체적인 원인 표시 X)
                flash('로그인 정보를 확인하세요.')
                
                # 실패 로깅 (관리자용)
                if user:
                    log_activity(user['id'], "login_failed", f"Failed login attempt for: {username}")
                else:
                    log_activity("unknown", "login_failed", f"Failed login attempt for unknown user: {username}")
                    
                return redirect(url_for('login'))
                
        except Exception as e:
            logger.error(f"로그인 에러: {e}")
            flash('로그인 처리 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user_id = session['user_id']
        log_activity(user_id, "logout", "User logged out")
        
    session.pop('user_id', None)
    session.pop('username', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 현재 사용자 조회
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        current_user = cursor.fetchone()

        # 검색어 필터링 (GET 파라미터 "q" 사용)
        keyword = request.args.get('q', '').strip()
        
        # XSS 방지를 위한 이스케이프
        safe_keyword = escape_html(keyword)
        
        if keyword:
            cursor.execute("SELECT * FROM product WHERE title LIKE ? ORDER BY created_at DESC", (f'%{keyword}%',))
        else:
            cursor.execute("SELECT * FROM product ORDER BY created_at DESC")
            
        all_products = cursor.fetchall()
        
        log_activity(session['user_id'], "view_dashboard", f"User viewed dashboard. Search: {keyword if keyword else 'none'}")
        
        return render_template('dashboard.html', products=all_products, user=current_user, keyword=safe_keyword)
        
    except Exception as e:
        logger.error(f"대시보드 에러: {e}")
        flash('대시보드를 불러오는 중 오류가 발생했습니다.')
        return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    try:
        db = get_db()
        cursor = db.cursor()
        
        if request.method == 'POST':
            bio = request.form.get('bio', '').strip()
            
            # 입력값 검증
            if len(bio) > 500:
                flash('소개글은 500자 이내로 작성해주세요.')
                return redirect(url_for('profile'))
            
            # XSS 방지를 위한 이스케이프
            safe_bio = escape_html(bio)
            
            cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (safe_bio, session['user_id']))
            db.commit()
            
            log_activity(session['user_id'], "update_profile", "User updated profile")
            
            flash('프로필이 업데이트되었습니다.')
            return redirect(url_for('profile'))
            
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        current_user = cursor.fetchone()
        
        return render_template('profile.html', user=current_user)
        
    except Exception as e:
        logger.error(f"프로필 에러: {e}")
        flash('프로필을 불러오는 중 오류가 발생했습니다.')
        return redirect(url_for('dashboard'))

@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        try:
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            price = request.form.get('price', '').strip()
            
            # 입력값 검증
            if not title or len(title) > 100:
                flash('상품명은 1~100자 사이여야 합니다.')
                return redirect(url_for('new_product'))
                
            if not description or len(description) > 1000:
                flash('상품 설명은 1~1000자 사이여야 합니다.')
                return redirect(url_for('new_product'))

            # 가격 검증: 숫자인지 확인
            if not price.isdigit() or int(price) < 0 or int(price) > 10000000:
                flash('가격은 0원에서 1000만원 사이의 숫자로만 입력해야 합니다.')
                return redirect(url_for('new_product'))
            
            # XSS 방지를 위한 이스케이프
            safe_title = escape_html(title)
            safe_description = escape_html(description)

            # 파일 업로드 처리
            file = request.files.get('image')
            image_path = None
            
            if file and file.filename:
                if not allowed_file(file.filename):
                    flash('허용되지 않는 파일 형식입니다. PNG, JPG, JPEG, GIF만 가능합니다.')
                    return redirect(url_for('new_product'))
                    
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                image_path = unique_filename
            
            db = get_db()
            cursor = db.cursor()
            product_id = str(uuid.uuid4())
            
            cursor.execute(
                "INSERT INTO product (id, title, description, price, seller_id, image) VALUES (?, ?, ?, ?, ?, ?)",
                (product_id, safe_title, safe_description, price, session['user_id'], image_path)
            )
            db.commit()
            
            log_activity(session['user_id'], "create_product", f"Created product: {title} (ID: {product_id})")
            
            flash('상품이 등록되었습니다.')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            logger.error(f"상품 등록 에러: {e}")
            flash('상품 등록 중 오류가 발생했습니다.')
            return redirect(url_for('new_product'))
            
    return render_template('new_product.html')

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        try:
            target_id = request.form.get('target_id', '').strip()
            reason = request.form.get('reason', '').strip()
            
            # 입력값 검증
            if not target_id or len(target_id) > 100:
                flash('신고 대상 ID가 유효하지 않습니다.')
                return redirect(url_for('report'))
                
            if not reason or len(reason) > 500:
                flash('신고 사유는 1~500자 사이여야 합니다.')
                return redirect(url_for('report'))
            
            # XSS 방지를 위한 이스케이프
            safe_reason = escape_html(reason)
            
            db = get_db()
            cursor = db.cursor()
            
            # 중복 신고 방지
            cursor.execute(
                "SELECT * FROM report WHERE reporter_id = ? AND target_id = ?", 
                (session['user_id'], target_id)
            )
            if cursor.fetchone():
                flash('이미 신고한 대상입니다.')
                return redirect(url_for('dashboard'))
            
            # 대상 존재 여부 확인
            cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
            user_target = cursor.fetchone()
            
            cursor.execute("SELECT * FROM product WHERE id = ?", (target_id,))
            product_target = cursor.fetchone()
            
            if not user_target and not product_target:
                flash('존재하지 않는 대상입니다.')
                return redirect(url_for('report'))
            
            # 자기 자신 신고 방지
            if user_target and user_target['id'] == session['user_id']:
                flash('자기 자신은 신고할 수 없습니다.')
                return redirect(url_for('report'))
            
            report_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
                (report_id, session['user_id'], target_id, safe_reason)
            )
            db.commit()
            
            # 관리자에게 실시간 알림
            socketio.emit('new_report', {'target': target_id, 'reason': safe_reason}, room='admin')
            
            log_activity(session['user_id'], "create_report", f"Reported: {target_id} - Reason: {reason[:50]}...")
            
            flash('신고가 접수되었습니다.')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            logger.error(f"신고 처리 에러: {e}")
            flash('신고 처리 중 오류가 발생했습니다.')
            return redirect(url_for('report'))
            
    return render_template('report.html')

@app.route('/admin/reports')
@admin_required
def admin_reports():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT r.*, u1.username AS reporter, u2.username AS target
            FROM report r
            LEFT JOIN user u1 ON r.reporter_id = u1.id
            LEFT JOIN user u2 ON r.target_id = u2.id
            ORDER BY r.created_at DESC
        """)
        reports = cursor.fetchall()
        
        log_activity(session['user_id'], "view_reports", "Admin viewed reports")
        
        return render_template('admin_reports.html', reports=reports)
        
    except Exception as e:
        logger.error(f"관리자 신고 목록 에러: {e}")
        flash('신고 내역을 불러오는 중 오류가 발생했습니다.')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user', methods=['POST'])
@admin_required
def delete_user():
    try:
        target_id = request.form.get('target_id', '').strip()
        
        if not target_id:
            flash('사용자 ID가 유효하지 않습니다.')
            return redirect(url_for('admin_dashboard'))
        
        db = get_db()
        cursor = db.cursor()
        
        # 대상 사용자 조회
        cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
        user = cursor.fetchone()
        
        if not user:
            flash('존재하지 않는 사용자입니다.')
            return redirect(url_for('admin_dashboard'))
        
        # 관리자 자신을 삭제하는 것 방지
        if user['username'] == 'admin':
            flash('관리자 계정은 삭제할 수 없습니다.')
            return redirect(url_for('admin_dashboard'))

        # 해당 유저의 상품, 거래, 지갑, 신고 등도 삭제
        cursor.execute("DELETE FROM product WHERE seller_id = ?", (target_id,))
        cursor.execute("DELETE FROM transactions WHERE sender_id = ? OR receiver_id = ?", (target_id, target_id))
        cursor.execute("DELETE FROM wallet WHERE user_id = ?", (target_id,))
        cursor.execute("DELETE FROM report WHERE reporter_id = ? OR target_id = ?", (target_id, target_id))
        cursor.execute("DELETE FROM user WHERE id = ?", (target_id,))

        db.commit()
        
        log_activity(session['user_id'], "delete_user", f"Admin deleted user: {user['username']} (ID: {target_id})")
        
        flash("사용자 계정 및 관련 정보가 모두 삭제되었습니다.")
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        logger.error(f"사용자 삭제 에러: {e}")
        flash('사용자 삭제 중 오류가 발생했습니다.')
        return redirect(url_for('admin_dashboard'))

@app.route('/product/<product_id>')
def view_product(product_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        
        if not product:
            flash('상품을 찾을 수 없습니다.')
            return redirect(url_for('dashboard'))
            
        # 판매자 정보 조회
        cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
        seller = cursor.fetchone()

        # 현재 사용자 정보도 함께 보내 수정/삭제 권한 체크에 사용
        current_user = None
        if 'user_id' in session:
            cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
            current_user = cursor.fetchone()
            
            # 활동 로깅
            log_activity(session['user_id'], "view_product", f"Viewed product: {product['title']} (ID: {product_id})")

        return render_template('view_product.html', product=product, seller=seller, user=current_user)
        
    except Exception as e:
        logger.error(f"상품 상세 조회 에러: {e}")
        flash('상품 정보를 불러오는 중 오류가 발생했습니다.')
        return redirect(url_for('dashboard'))

@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 해당 product_id에 해당하는 상품 조회
        cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        
        # 상품이 없거나, 현재 사용자가 이 상품의 소유자가 아닐 경우
        if not product:
            flash('존재하지 않는 상품입니다.')
            return redirect(url_for('dashboard'))
            
        if product['seller_id'] != session['user_id']:
            log_activity(session['user_id'], "unauthorized_edit", f"Unauthorized edit attempt: Product {product_id}")
            flash('수정 권한이 없습니다.')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            price = request.form.get('price', '').strip()

            # 입력값 검증
            if not title or len(title) > 100:
                flash('상품명은 1~100자 사이여야 합니다.')
                return redirect(url_for('edit_product', product_id=product_id))
                
            if not description or len(description) > 1000:
                flash('상품 설명은 1~1000자 사이여야 합니다.')
                return redirect(url_for('edit_product', product_id=product_id))

            # 가격 검증: 숫자인지 확인
            if not price.isdigit() or int(price) < 0 or int(price) > 10000000:
                flash('가격은 0원에서 1000만원 사이의 숫자로만 입력해야 합니다.')
                return redirect(url_for('edit_product', product_id=product_id))
                
            # XSS 방지를 위한 이스케이프
            safe_title = escape_html(title)
            safe_description = escape_html(description)
            
            # 이미지 업데이트를 위해 파일을 받았는지 확인
            file = request.files.get('image')
            image_path = product['image']  # 기존 이미지 경로(없으면 None)
            
            if file and file.filename:
                if not allowed_file(file.filename):
                    flash('허용되지 않는 파일 형식입니다. PNG, JPG, JPEG, GIF만 가능합니다.')
                    return redirect(url_for('edit_product', product_id=product_id))
                    
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                image_path = unique_filename  # 새 이미지 파일명으로 업데이트
            
            # DB 업데이트
            cursor.execute("""
                UPDATE product 
                SET title = ?, description = ?, price = ?, image = ?
                WHERE id = ?
            """, (safe_title, safe_description, price, image_path, product_id))
            db.commit()
            
            log_activity(session['user_id'], "edit_product", f"Edited product: {title} (ID: {product_id})")
            
            flash('상품이 성공적으로 수정되었습니다.')
            return redirect(url_for('view_product', product_id=product_id))
        
        # GET 메소드면 수정 폼 페이지 렌더링
        return render_template('edit_product.html', product=product)
        
    except Exception as e:
        logger.error(f"상품 수정 에러: {e}")
        flash('상품 수정 중 오류가 발생했습니다.')
        return redirect(url_for('dashboard'))

@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 해당 상품을 조회
        cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
        product = cursor.fetchone()

        if not product:
            flash('존재하지 않는 상품입니다.')
            return redirect(url_for('dashboard'))
            
        if product['seller_id'] != session['user_id']:
            log_activity(session['user_id'], "unauthorized_delete", f"Unauthorized delete attempt: Product {product_id}")
            flash('삭제 권한이 없습니다.')
            return redirect(url_for('dashboard'))

        # 상품 삭제
        cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
        db.commit()
        
        log_activity(session['user_id'], "delete_product", f"Deleted product: {product['title']} (ID: {product_id})")

        flash('상품이 성공적으로 삭제되었습니다.')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"상품 삭제 에러: {e}")
        flash('상품 삭제 중 오류가 발생했습니다.')
        return redirect(url_for('dashboard'))

# --- 지갑 및 송금 관련 라우트 추가 ---

@app.route('/wallet')
@login_required
def wallet():
    try:
        db = get_db()
        cursor = db.cursor()

        # 잔액
        cursor.execute("SELECT balance FROM wallet WHERE user_id = ?", (session['user_id'],))
        balance_row = cursor.fetchone()
        balance = balance_row['balance'] if balance_row else 0

        # 내가 보낸 거래
        cursor.execute("""
            SELECT t.*, u.username AS receiver_name
            FROM transactions t
            JOIN user u ON t.receiver_id = u.id
            WHERE t.sender_id = ?
            ORDER BY t.timestamp DESC
        """, (session['user_id'],))
        sent_transactions = cursor.fetchall()

        # 내가 받은 거래
        cursor.execute("""
            SELECT t.*, u.username AS sender_name
            FROM transactions t
            JOIN user u ON t.sender_id = u.id
            WHERE t.receiver_id = ?
            ORDER BY t.timestamp DESC
        """, (session['user_id'],))
        received_transactions = cursor.fetchall()
        
        log_activity(session['user_id'], "view_wallet", f"Viewed wallet balance: {balance}")

        return render_template('wallet.html', balance=balance, 
                            sent_transactions=sent_transactions,
                            received_transactions=received_transactions)
                            
    except Exception as e:
        logger.error(f"지갑 조회 에러: {e}")
        flash('지갑 정보를 불러오는 중 오류가 발생했습니다.')
        return redirect(url_for('dashboard'))

@app.route('/product/<product_id>/pay', methods=['POST'])
@login_required
def pay_to_seller(product_id):
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 상품 정보 가져오기
        cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        
        if not product:
            flash('상품이 존재하지 않습니다.')
            return redirect(url_for('dashboard'))

        sender_id = session['user_id']
        receiver_id = product['seller_id']
        
        # 자신의 상품은 구매할 수 없음
        if sender_id == receiver_id:
            flash('자신의 상품은 구매할 수 없습니다.')
            return redirect(url_for('view_product', product_id=product_id))
            
        amount = int(product['price'])

        # 잔액 확인
        cursor.execute("SELECT balance FROM wallet WHERE user_id = ?", (sender_id,))
        sender_balance = cursor.fetchone()['balance']
        
        if sender_balance < amount:
            flash('잔액이 부족합니다.')
            return redirect(url_for('view_product', product_id=product_id))

        # 트랜잭션 시작
        db.execute("BEGIN TRANSACTION")
        
        try:
            # 송금 처리 (트랜잭션)
            cursor.execute("UPDATE wallet SET balance = balance - ? WHERE user_id = ?", (amount, sender_id))
            cursor.execute("UPDATE wallet SET balance = balance + ? WHERE user_id = ?", (amount, receiver_id))
            
            transaction_id = str(uuid.uuid4())
            cursor.execute("INSERT INTO transactions (id, sender_id, receiver_id, amount) VALUES (?, ?, ?, ?)",
                        (transaction_id, sender_id, receiver_id, amount))
            
            # 트랜잭션 커밋
            db.commit()
            
            # 활동 로깅
            log_activity(session['user_id'], "payment", f"Paid {amount} to {receiver_id} for product {product_id}")
            
            # 송금 알림 처리
            try:
                # 현재 사용자 이름 가져오기 
                cursor.execute("SELECT username FROM user WHERE id = ?", (sender_id,))
                sender_name = cursor.fetchone()['username']
                
                # 채팅방 ID 생성
                room_id = f"room_{'_'.join(sorted([sender_id, receiver_id]))}"
                
                # 메시지 전송 (요청 컨텍스트 내부에서만 작동)
                socketio.emit('private_message', {
                    'username': '시스템',
                    'message': f'{sender_name}님이 {amount}원을 결제했습니다.'
                }, room=room_id)
                
            except Exception as e:
                # 로그에 기록만 하고 주요 기능은 계속 진행
                logger.error(f"송금 알림 에러: {e}")

            flash('송금이 완료되었습니다.')
            return redirect(url_for('wallet'))
            
        except Exception as e:
            # 트랜잭션 롤백
            db.execute("ROLLBACK")
            logger.error(f"송금 처리 에러: {e}")
            flash('송금 처리 중 오류가 발생했습니다.')
            return redirect(url_for('view_product', product_id=product_id))
            
    except Exception as e:
        logger.error(f"상품 구매 에러: {e}")
        flash('상품 구매 중 오류가 발생했습니다.')
        return redirect(url_for('dashboard'))

@app.route('/wallet/topup', methods=['POST'])
@login_required
def topup_wallet():
    try:
        amount = request.form.get('amount', '0')
        
        # 입력값 검증
        if not amount.isdigit() or int(amount) <= 0 or int(amount) > 1000000:
            flash("충전 금액은 1 ~ 1,000,000원 사이여야 합니다.")
            return redirect(url_for('wallet'))
            
        amount = int(amount)
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE wallet SET balance = balance + ? WHERE user_id = ?", (amount, session['user_id']))
        db.commit()
        
        log_activity(session['user_id'], "wallet_topup", f"Topped up wallet: {amount}")
        
        flash(f"{amount}원이 충전되었습니다!")
        return redirect(url_for('wallet'))
        
    except Exception as e:
        logger.error(f"지갑 충전 에러: {e}")
        flash('지갑 충전 중 오류가 발생했습니다.')
        return redirect(url_for('wallet'))

# --- 1대1 채팅을 위한 라우트 추가 ---

@app.route('/chat')
@login_required
def chat_list():
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 현재 사용자 제외한 모든 사용자 조회 (간단한 예시)
        cursor.execute("SELECT * FROM user WHERE id != ?", (session['user_id'],))
        users = cursor.fetchall()
        
        log_activity(session['user_id'], "view_chat_list", "Viewed chat list")
        
        return render_template('chat_list.html', users=users)
        
    except Exception as e:
        logger.error(f"채팅 목록 조회 에러: {e}")
        flash('채팅 목록을 불러오는 중 오류가 발생했습니다.')
        return redirect(url_for('dashboard'))

@app.route('/chat/<target_id>')
@login_required
def private_chat(target_id):
    try:
        # 대상 ID 검증
        if not target_id or len(target_id) > 100:
            flash('채팅 대상이 유효하지 않습니다.')
            return redirect(url_for('chat_list'))
            
        db = get_db()
        cursor = db.cursor()
        
        # 대상 사용자 정보 조회
        cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
        target_user = cursor.fetchone()
        
        if not target_user:
            flash("대상 사용자를 찾을 수 없습니다.")
            return redirect(url_for('chat_list'))
            
        # 현재 사용자 정보 조회
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        current_user = cursor.fetchone()
        
        # 두 사용자 간 채팅방 ID는 두 ID를 정렬해서 생성 (항상 동일한 방)
        room = f"room_{'_'.join(sorted([current_user['id'], target_user['id']]))}"
        
        log_activity(session['user_id'], "join_chat", f"Joined chat with: {target_user['username']}")
        
        return render_template('private_chat.html', room=room, target_user=target_user, current_user=current_user)
        
    except Exception as e:
        logger.error(f"채팅방 접속 에러: {e}")
        flash('채팅방 접속 중 오류가 발생했습니다.')
        return redirect(url_for('chat_list'))

@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    try:
        db = get_db()
        cursor = db.cursor()

        if request.method == 'POST':
            target_id = request.form.get('target_id', '').strip()
            action = request.form.get('action', '').strip()

            if not target_id:
                flash('대상 ID가 유효하지 않습니다.')
                return redirect(url_for('admin_dashboard'))
                
            # 관리자 자신을 차단하는 것 방지
            cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
            target_user = cursor.fetchone()
            
            if not target_user:
                flash('존재하지 않는 사용자입니다.')
                return redirect(url_for('admin_dashboard'))
                
            if target_user['username'] == 'admin':
                flash('관리자 계정은 차단할 수 없습니다.')
                return redirect(url_for('admin_dashboard'))

            if action == 'block':
                # 정지 기간 해석
                period = request.form.get('suspend_period', '1m')
                now = datetime.now()

                suspend_map = {
                    '1m': now + timedelta(days=30),
                    '3m': now + timedelta(days=90),
                    '6m': now + timedelta(days=180),
                    '1y': now + timedelta(days=365),
                    '3y': now + timedelta(days=365*3),
                }
                suspended_until = suspend_map.get(period)

                # 차단 처리
                cursor.execute("""
                    UPDATE user
                    SET is_blocked = 1, suspended_until = ?
                    WHERE id = ?
                """, (suspended_until.strftime("%Y-%m-%d") if suspended_until else None, target_id))

                # 상품 삭제 체크 시
                if request.form.get('delete_products') == 'yes':
                    cursor.execute("DELETE FROM product WHERE seller_id = ?", (target_id,))
                    flash('해당 유저의 상품을 삭제했습니다.')

                log_activity(session['user_id'], "block_user", f"Admin blocked user: {target_user['username']} until {suspended_until.strftime('%Y-%m-%d')}")
                flash('사용자가 차단되었습니다.')

            elif action == 'unblock':
                cursor.execute("""
                    UPDATE user
                    SET is_blocked = 0, suspended_until = NULL
                    WHERE id = ?
                """, (target_id,))
                
                log_activity(session['user_id'], "unblock_user", f"Admin unblocked user: {target_user['username']}")
                flash('사용자 차단을 해제했습니다.')

            db.commit()
            return redirect(url_for('admin_dashboard'))

        cursor.execute("SELECT * FROM user")
        users = cursor.fetchall()
        
        log_activity(session['user_id'], "view_admin", "Admin viewed user management page")

        return render_template('admin_users.html', users=users)
        
    except Exception as e:
        logger.error(f"관리자 대시보드 에러: {e}")
        flash('관리자 페이지를 불러오는 중 오류가 발생했습니다.')
        return redirect(url_for('dashboard'))

@app.route('/admin/suspend', methods=['POST'])
@admin_required
def suspend_user():
    try:
        user_id = request.form.get('target_id', '').strip()
        period_str = request.form.get('period_months', '1')
        
        if not user_id:
            flash('대상 ID가 유효하지 않습니다.')
            return redirect(url_for('admin_dashboard'))
            
        # 기간 입력 검증
        try:
            period = int(period_str)
            if period < 1 or period > 36:
                period = 1  # 기본값
        except ValueError:
            period = 1  # 기본값
            
        suspended_until = (datetime.now() + timedelta(days=30 * period)).strftime('%Y-%m-%d')

        db = get_db()
        cursor = db.cursor()
        
        # 대상 사용자 조회
        cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            flash('존재하지 않는 사용자입니다.')
            return redirect(url_for('admin_dashboard'))
            
        if user['username'] == 'admin':
            flash('관리자 계정은 차단할 수 없습니다.')
            return redirect(url_for('admin_dashboard'))

        # 유저의 상품 삭제
        cursor.execute("DELETE FROM product WHERE seller_id = ?", (user_id,))

        # 유저 계정 차단 + 휴면 처리
        cursor.execute("UPDATE user SET is_blocked = 1, suspended_until = ? WHERE id = ?", (suspended_until, user_id))

        db.commit()
        
        log_activity(session['user_id'], "suspend_user", f"Admin suspended user: {user['username']} for {period} months")
        
        flash(f'유저 차단 및 상품 삭제 완료. 활동 정지 기간: {period}개월')
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        logger.error(f"사용자 정지 에러: {e}")
        flash('사용자 정지 처리 중 오류가 발생했습니다.')
        return redirect(url_for('admin_dashboard'))

# --- 소켓 이벤트 핸들러 ---

@socketio.on('join_admin')
def join_admin():
    if session.get('username') == 'admin':
        join_room('admin')
        log_activity(session['user_id'], "join_admin_room", "Admin joined admin notification room")

@socketio.on('join')
def on_join(data):
    try:
        room = data.get('room', '')
        if not room:
            return
            
        join_room(room)
        
        # XSS 방지
        username = escape_html(data.get('username', ''))
        
        # 필요시 입장 메시지 전송 가능
        # emit('private_message', {'username': '시스템', 'message': f"{username}님이 입장하셨습니다."}, room=room)
        
        if 'user_id' in session:
            log_activity(session['user_id'], "join_chat_room", f"Joined chat room: {room}")
            
    except Exception as e:
        logger.error(f"채팅방 입장 에러: {e}")

@socketio.on('private_message')
def on_private_message(data):
    try:
        room = data.get('room', '')
        username = data.get('username', '')
        message = data.get('message', '')
        
        if not room or not username or not message:
            return
            
        # XSS 방지
        safe_username = escape_html(username)
        safe_message = escape_html(message)
        
        # 욕설/부적절 단어 필터링 (예시)
        inappropriate_words = ['바보', '멍청이', '욕설', 'badword']
        for word in inappropriate_words:
            if word in safe_message.lower():
                safe_message = safe_message.replace(word, '***')
                
        socketio.emit('private_message', {'username': safe_username, 'message': safe_message}, room=room)
        
        if 'user_id' in session:
            log_activity(session['user_id'], "send_message", f"Sent message in room: {room}")
            
    except Exception as e:
        logger.error(f"메시지 전송 에러: {e}")

@socketio.on('send_message')
def handle_send_message_event(data):
    try:
        username = data.get('username', '')
        message = data.get('message', '')
        
        if not username or not message:
            return
            
        # XSS 방지
        safe_username = escape_html(username)
        safe_message = escape_html(message)
        
        data['username'] = safe_username
        data['message'] = safe_message
        data['message_id'] = str(uuid.uuid4())
        
        send(data, broadcast=True)
        
        if 'user_id' in session:
            log_activity(session['user_id'], "broadcast_message", "Sent broadcast message")
            
    except Exception as e:
        logger.error(f"전체 메시지 전송 에러: {e}")

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        # 파일명 검증 (경로 순회 방지)
        if '..' in filename or filename.startswith('/'):
            abort(404)
            
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
        
    except Exception as e:
        logger.error(f"파일 다운로드 에러: {e}")
        abort(404)

if __name__ == '__main__':
    init_db()  # 테이블 초기화를 진행
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
