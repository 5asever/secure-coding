import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask_wtf import CSRFProtect
import re
import html
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from collections import defaultdict, deque
import time
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import generate_csrf    

# 사용자별 메시지 타임스탬프 저장 (기억해야 할 시간만 유지)
message_times = defaultdict(lambda: deque(maxlen=10))  # 최근 10개만 추적

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['WTF_CSRF_CHECK_REFERER'] = False

# CSRF 토큰 발급/검증 활성화
csrf = CSRFProtect(app)

# === 추가된 부분: 세션 쿠키 보안 설정 ===
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    REMEMBER_COOKIE_SECURE=True,
)

# 1) 세션을 영구 세션으로 설정 & 만료 시간 지정
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# SQLAlchemy 설정
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///market.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SQLAlchemy 객체 생성
db = SQLAlchemy(app)
migrate = Migrate(app, db)

MAX_FAILS = 5

# -----------------------------
# 파일 업로드 관련 설정
# -----------------------------
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'upload')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 최대 16MB 파일 제한

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

socketio = SocketIO(app, manage_session=False)

# -----------------------------
# 모델 정의
# -----------------------------
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.String(36), primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    bio = db.Column(db.Text, nullable=True)
    is_blocked = db.Column(db.Boolean, default=False)
    suspended_until = db.Column(db.String(10), nullable=True)
    login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.String(30), nullable=True)
    
    # 관계 설정
    products = db.relationship('Product', backref='seller', lazy=True)
    wallet = db.relationship('Wallet', backref='user', uselist=False, lazy=True)
    sent_transactions = db.relationship('Transaction', 
                                       foreign_keys='Transaction.sender_id',
                                       backref='sender', lazy=True)
    received_transactions = db.relationship('Transaction', 
                                           foreign_keys='Transaction.receiver_id',
                                           backref='receiver', lazy=True)
    reports_filed = db.relationship('Report', 
                                   foreign_keys='Report.reporter_id',
                                   backref='reporter', lazy=True)
    reports_received = db.relationship('Report', 
                                      foreign_keys='Report.target_id',
                                      backref='target', lazy=True)

class Product(db.Model):
    __tablename__ = 'product'
    id = db.Column(db.String(36), primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.String(20), nullable=False)
    seller_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    image = db.Column(db.String(100), nullable=True)

class Report(db.Model):
    __tablename__ = 'report'
    id = db.Column(db.String(36), primary_key=True)
    reporter_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    target_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Wallet(db.Model):
    __tablename__ = 'wallet'
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), primary_key=True)
    balance = db.Column(db.Integer, default=0, nullable=False)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.String(36), primary_key=True)
    sender_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# -----------------------------
# 유틸리티 함수
# -----------------------------
@app.after_request
def apply_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self' ws:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    return response


@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 민감 작업 전 비밀번호 재인증이 5분 이내에 이뤄졌는지 검사
def require_reauth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        reauth = session.get('reauth_time')
        if not reauth or (datetime.utcnow() - datetime.fromisoformat(reauth)).total_seconds() > 300:
            # 재인증 필요
            return redirect(url_for('reauth', next=request.endpoint, **request.view_args))
        return f(*args, **kwargs)
    return decorated

@app.before_request
def check_session_timeout():
    # 로그인 상태가 아니면 패스
    if 'user_id' not in session:
        return
        
    # 세션 영구 설정
    session.permanent = True
    
    now = datetime.utcnow()
    last = session.get('last_activity')
    if last:
        elapsed = now - datetime.fromisoformat(last)
        if elapsed > app.permanent_session_lifetime:
            session.clear()
            flash('30분 동안 활동이 없어 자동 로그아웃 되었습니다.')
            return redirect(url_for('login'))

    # 마지막 활동 시간 갱신
    session['last_activity'] = now.isoformat()

def init_db():
    with app.app_context():
        # 모든 테이블 생성
        db.create_all()

        # 관리자 계정(admin)이 없으면 생성
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin_id = str(uuid.uuid4())
            admin_pw_hashed = generate_password_hash('admin')

            # 관리자 사용자 추가
            admin = User(
                id=admin_id,
                username='admin',
                password=admin_pw_hashed
            )
            db.session.add(admin)

            # 관리자 지갑 추가
            admin_wallet = Wallet(
                user_id=admin_id,
                balance=100000
            )
            db.session.add(admin_wallet)

            db.session.commit()
            print("[INFO] 관리자 계정(admin) 생성 완료")

# -----------------------------
# 라우트 설정
# -----------------------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# --- 서버측 검증용 정규식 정의 ---
# 사용자명: 3~20자, 영문/숫자/밑줄만 허용
USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,20}$')
# 비밀번호: 8~50자, 최소 영문·숫자·특수문자 각각 1회 이상 포함
PASSWORD_RE = re.compile(
    r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\'\\:"|,.<>\/?]).{8,50}$'
)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        raw_u = request.form.get('username','').strip()
        raw_p = request.form.get('password','')
        # 길이 검증
        if not (3<=len(raw_u)<=20):
            flash('사용자명은 3~20자여야 합니다.'); return redirect(url_for('register'))
        if not (8<=len(raw_p)<=50):
            flash('비밀번호는 8~50자 사이여야 합니다.'); return redirect(url_for('register'))
        # 형식 검증
        if not USERNAME_RE.match(raw_u):
            flash('사용자명은 영문/숫자/_만 가능합니다.'); return redirect(url_for('register'))
        if not PASSWORD_RE.match(raw_p):
            flash('비밀번호에 영문·숫자·특수문자 모두 포함해주세요.'); return redirect(url_for('register'))
        # XSS 대비
        username = html.escape(raw_u)
        pwd_hash = generate_password_hash(raw_p)
        
        # 중복 체크
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('이미 존재하는 사용자입니다.'); return redirect(url_for('register'))
        
        # 신규 등록
        uid = str(uuid.uuid4())
        new_user = User(id=uid, username=username, password=pwd_hash)
        new_wallet = Wallet(user_id=uid, balance=10000)
        
        db.session.add(new_user)
        db.session.add(new_wallet)
        db.session.commit()
        
        flash('회원가입 완료! 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        u = request.form['username']
        p = request.form['password']
        now = datetime.utcnow()

        # 1) 사용자 조회
        user = User.query.filter_by(username=u).first()
        if not user:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

        # 2) 잠금 상태 검사
        fails = user.login_attempts
        last = user.last_login_attempt
        if last:
            last_dt = datetime.fromisoformat(last)
            if fails >= MAX_FAILS and now - last_dt < timedelta(minutes=30):
                flash('로그인 5회 실패로 30분간 잠금되었습니다.')
                return redirect(url_for('login'))
            if now - last_dt >= timedelta(minutes=30):
                # 잠금 해제
                fails = 0

        # 3) 비밀번호 검증
        if check_password_hash(user.password, p):
            # 성공 시 실패 카운터 리셋
            user.login_attempts = 0
            user.last_login_attempt = None
            db.session.commit()
            
            # 차단 상태 검사
            if user.is_blocked:
                until = user.suspended_until
                if until and datetime.strptime(until,"%Y-%m-%d") > datetime.now():
                    flash(f"{until}까지 정지된 계정입니다.")
                    return redirect(url_for('login'))
                # 자동 해제
                user.is_blocked = False
                user.suspended_until = None
                db.session.commit()
                
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
            session['last_activity'] = now.isoformat()
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            # 실패 시 카운터 증가 및 시간 갱신
            user.login_attempts = fails + 1
            user.last_login_attempt = now.isoformat()
            db.session.commit()

            if user.login_attempts >= MAX_FAILS:
                flash('로그인 5회 실패로 30분간 잠금됩니다.')
            else:
                flash(f'로그인 실패 ({user.login_attempts}/{MAX_FAILS})')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 현재 사용자 조회
    current_user = User.query.get(session['user_id'])

    # 검색어 필터링 (GET 파라미터 "q" 사용)
    keyword = request.args.get('q', '').strip()
    if keyword:
        # XSS 방지를 위한 이스케이프 처리
        safe_keyword = html.escape(keyword)
        all_products = Product.query.filter(Product.title.like(f'%{safe_keyword}%')).all()
    else:
        all_products = Product.query.all()

    return render_template('dashboard.html', products=all_products, user=current_user, keyword=keyword)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        # XSS 방지를 위한 이스케이프 처리
        bio = html.escape(request.form.get('bio', ''))
        current_user.bio = bio
        db.session.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
        
    return render_template('profile.html', user=current_user)

@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            # 입력값 추출 및 공백 제거
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

            if not price.isdigit() or not (0 <= int(price) <= 10000000):
                flash('가격은 0원에서 1000만원 사이의 숫자로만 입력해야 합니다.')
                return redirect(url_for('new_product'))

            # XSS 방지 처리
            title = html.escape(title)
            description = html.escape(description)

            # 파일 업로드 처리
            file = request.files.get('image')
            image_path = None
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                image_path = unique_filename  # 저장 경로

            # DB에 저장
            product_id = str(uuid.uuid4())
            new_product = Product(
                id=product_id,
                title=title,
                description=description,
                price=price,
                seller_id=session['user_id'],
                image=image_path
            )
            db.session.add(new_product)
            db.session.commit()

            flash('상품이 등록되었습니다.')
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            flash('상품 등록 중 오류가 발생했습니다. 나중에 다시 시도해주세요.')
            print(f"[ERROR] 상품 등록 실패: {e}")  # 배포 시 logging 처리 권장

    return render_template('new_product.html')

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # 📌 [1] 신고 사유 가져오기
        reason = html.escape(request.form['reason'])

        # 📌 [2] 대상 ID 가져오기
        target_id = request.form.get('target_id')
        if not target_id:
            flash('신고 대상이 없습니다.')
            return redirect(url_for('dashboard'))

        # 📌 [3] 자기 자신 신고 방지
        if target_id == session['user_id']:
            flash('자기 자신을 신고할 수 없습니다.')
            return redirect(url_for('dashboard'))

        # ✅ [4] 동일 대상 중복 신고 방지
        existing_report = Report.query.filter_by(
            reporter_id=session['user_id'], 
            target_id=target_id
        ).first()
        
        if existing_report:
            flash("이미 신고한 사용자입니다.")
            return redirect(url_for('dashboard'))

        # ✅ [5] 하루 신고 횟수 제한 (최대 5회)
        today = datetime.now().date()
        today_reports_count = Report.query.filter(
            Report.reporter_id == session['user_id'],
            db.func.date(Report.timestamp) == today
        ).count()
        
        if today_reports_count >= 5:
            flash("하루 신고 가능 횟수를 초과했습니다.")
            return redirect(url_for('dashboard'))

        # ✅ [6] 신고 기록 저장
        report_id = str(uuid.uuid4())
        new_report = Report(
            id=report_id,
            reporter_id=session['user_id'],
            target_id=target_id,
            reason=reason,
            timestamp=datetime.utcnow()
        )
        db.session.add(new_report)
        db.session.commit()

        # 관리자에게 알림
        socketio.emit('new_report', {'target': target_id, 'reason': reason}, room='admin')

        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html')

@app.route('/admin/reports')
def admin_reports():
    if 'user_id' not in session or session.get('username') != 'admin':
        flash('접근 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    # 모든 신고 내역 조회 (조인 사용)
    reports = db.session.query(
        Report, 
        User.username.label('reporter_name')
    ).join(
        User, 
        Report.reporter_id == User.id
    ).all()

    # 대상 사용자 이름 가져오기
    for report, _ in reports:
        target = User.query.get(report.target_id)
        report.target_name = target.username if target else "알 수 없음"

    return render_template('admin_reports.html', reports=reports)

@app.route('/admin/delete_user', methods=['POST'])
@require_reauth
def delete_user():
    if 'user_id' not in session or session.get('username') != 'admin':
        flash("관리자만 접근 가능합니다.")
        return redirect(url_for('dashboard'))

    target_id = request.form.get('target_id')
    
    # 자기 자신 삭제 방지
    if target_id == session['user_id']:
        flash("자기 자신을 삭제할 수 없습니다.")
        return redirect(url_for('admin_dashboard'))

    # 대상 사용자 존재 확인
    user = User.query.get(target_id)
    if not user:
        flash("존재하지 않는 사용자입니다.")
        return redirect(url_for('admin_dashboard'))

    try:
        # 해당 유저의 상품, 거래, 지갑, 신고 등도 삭제
        Product.query.filter_by(seller_id=target_id).delete()
        Transaction.query.filter((Transaction.sender_id == target_id) | 
                                (Transaction.receiver_id == target_id)).delete()
        Wallet.query.filter_by(user_id=target_id).delete()
        Report.query.filter((Report.reporter_id == target_id) | 
                           (Report.target_id == target_id)).delete()
        db.session.delete(user)
        db.session.commit()
        
        flash("사용자 계정 및 관련 정보가 모두 삭제되었습니다.")
    except Exception as e:
        db.session.rollback()
        flash("사용자 삭제 중 오류가 발생했습니다.")
        print(f"사용자 삭제 오류: {e}")
        
    return redirect(url_for('admin_dashboard'))

@app.route('/product/<product_id>')
def view_product(product_id):
    # 상품 정보 조회
    product = Product.query.get(product_id)
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 판매자 정보 조회
    seller = User.query.get(product.seller_id)

    # 현재 사용자 정보 조회
    current_user = None
    if 'user_id' in session:
        current_user = User.query.get(session['user_id'])

    return render_template('view_product.html', product=product, seller=seller, user=current_user)

@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))
    
    # 해당 product_id에 해당하는 상품 조회
    product = Product.query.get(product_id)
    
    # 상품이 없거나, 현재 사용자가 이 상품의 소유자가 아닐 경우
    if not product:
        flash('존재하지 않는 상품입니다.')
        return redirect(url_for('dashboard'))
    if product.seller_id != session['user_id'] and session.get('username') != 'admin':
        flash('수정 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # XSS 방지를 위한 이스케이프 처리
        title = html.escape(request.form['title'])
        description = html.escape(request.form['description'])
        price = request.form['price']

        # 가격 검증: 숫자인지 확인
        if not price.isdigit():
            flash('가격은 숫자로만 입력해야 합니다.')
            return redirect(url_for('edit_product', product_id=product_id))
        
        # 이미지 업데이트를 위해 파일을 받았는지 확인
        file = request.files.get('image')
        image_path = product.image  # 기존 이미지 경로(없으면 None)
        
        if file and file.filename and allowed_file(file.filename):
            # 파일 업로드 처리
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            image_path = unique_filename  # 새 이미지 파일명으로 업데이트
        
        # DB 업데이트
        product.title = title
        product.description = description
        product.price = price
        product.image = image_path
        db.session.commit()
        
        flash('상품이 성공적으로 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    # GET 메소드면 수정 폼 페이지 렌더링
    return render_template('edit_product.html', product=product)

@app.route('/product/<product_id>/delete', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    # 해당 상품을 조회
    product = Product.query.get(product_id)

    if not product:
        flash('존재하지 않는 상품입니다.')
        return redirect(url_for('dashboard'))
    if product.seller_id != session['user_id'] and session.get('username') != 'admin':
        flash('삭제 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    # 상품 삭제
    db.session.delete(product)
    db.session.commit()

    flash('상품이 성공적으로 삭제되었습니다.')
    return redirect(url_for('dashboard'))

@app.route('/wallet')
def wallet():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 잔액 조회
    user_wallet = Wallet.query.get(session['user_id'])
    balance = user_wallet.balance if user_wallet else 0

    # 내가 보낸 거래
    sent_transactions = Transaction.query.filter_by(sender_id=session['user_id']).order_by(Transaction.timestamp.desc()).all()

    # 내가 받은 거래
    received_transactions = Transaction.query.filter_by(receiver_id=session['user_id']).order_by(Transaction.timestamp.desc()).all()

    return render_template('wallet.html', balance=balance, 
                           sent_transactions=sent_transactions,
                           received_transactions=received_transactions)

@app.route('/product/<product_id>/pay', methods=['POST'])
def pay_to_seller(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))
    
    # 상품 정보 가져오기
    product = Product.query.get(product_id)
    if not product:
        flash('상품이 존재하지 않습니다.')
        return redirect(url_for('dashboard'))

    sender_id = session['user_id']
    receiver_id = product.seller_id
    
    # 자신의 상품은 구매할 수 없음
    if sender_id == receiver_id:
        flash('자신의 상품은 구매할 수 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))
        
    try:
        amount = int(product.price)
    except ValueError:
        flash('상품 가격이 올바르지 않습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    # 잔액 확인
    sender_wallet = Wallet.query.get(sender_id)
    if not sender_wallet or sender_wallet.balance < amount:
        flash('잔액이 부족합니다.')
        return redirect(url_for('view_product', product_id=product_id))

    # 송금 처리 (트랜잭션)
    try:
        # 송금자 잔액 감소
        sender_wallet.balance -= amount
        
        # 수령자 잔액 증가
        receiver_wallet = Wallet.query.get(receiver_id)
        if not receiver_wallet:
            receiver_wallet = Wallet(user_id=receiver_id, balance=amount)
            db.session.add(receiver_wallet)
        else:
            receiver_wallet.balance += amount
        
        # 거래 기록 생성
        transaction = Transaction(
            id=str(uuid.uuid4()),
            sender_id=sender_id,
            receiver_id=receiver_id,
            amount=amount,
            timestamp=datetime.utcnow()
        )
        db.session.add(transaction)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash('결제 처리 중 오류가 발생했습니다.')
        print(f"결제 오류: {e}")
        return redirect(url_for('view_product', product_id=product_id))
    
    # 송금 알림 처리
    try:
        # 현재 사용자 이름 가져오기 
        sender = User.query.get(sender_id)
        sender_name = sender.username
        
        # 채팅방 ID 생성
        room_id = f"room_{'_'.join(sorted([sender_id, receiver_id]))}"
        
        # 메시지 전송
        socketio.emit('private_message', {
            'username': '시스템',
            'message': f'{sender_name}님이 {amount}원을 결제했습니다.'
        }, room=room_id)
    except Exception as e:
        # 로그에 기록만 하고 주요 기능은 계속 진행
        print(f"송금 알림 에러: {e}")

    flash('송금이 완료되었습니다.')
    return redirect(url_for('wallet'))

@app.route('/wallet/topup', methods=['POST'])
def topup_wallet():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        amount = int(request.form.get('amount', 0))
        if amount <= 0 or amount > 1000000:  # 상한선 추가
            flash("올바른 금액을 입력하세요 (1~1,000,000원).")
            return redirect(url_for('wallet'))
    except ValueError:
        flash("숫자만 입력 가능합니다.")
        return redirect(url_for('wallet'))

    # 지갑 잔액 증가
    wallet = Wallet.query.get(session['user_id'])
    if not wallet:
        wallet = Wallet(user_id=session['user_id'], balance=amount)
        db.session.add(wallet)
    else:
        wallet.balance += amount
    
    db.session.commit()
    flash(f"{amount}원이 충전되었습니다!")
    return redirect(url_for('wallet'))

@app.route('/chat')
def chat_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 현재 사용자 제외한 모든 사용자 조회
    users = User.query.filter(User.id != session['user_id']).all()
    return render_template('chat_list.html', users=users)

@app.route('/chat/<target_id>')
def private_chat(target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 대상 사용자 정보 조회
    target_user = User.query.get(target_id)
    if not target_user:
        flash("대상 사용자를 찾을 수 없습니다.")
        return redirect(url_for('chat_list'))
    
    # 현재 사용자 정보 조회
    current_user = User.query.get(session['user_id'])
    
    # 두 사용자 간 채팅방 ID는 두 ID를 정렬해서 생성 (항상 동일한 방)
    room = f"room_{'_'.join(sorted([current_user.id, target_user.id]))}"
    return render_template('private_chat.html', room=room, target_user=target_user, current_user=current_user)

@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # 현재 사용자 조회
    user = User.query.get(session['user_id'])

    if user.username != 'admin':
        flash('접근 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        target_id = request.form['target_id']
        action = request.form['action']
        
        # 대상 사용자 조회
        target_user = User.query.get(target_id)
        if not target_user:
            flash('존재하지 않는 사용자입니다.')
            return redirect(url_for('admin_dashboard'))

        if action == 'block':
            # 정지 기간 해석
            period = request.form.get('suspend_period')
            from datetime import datetime, timedelta
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
            target_user.is_blocked = True
            target_user.suspended_until = suspended_until.strftime("%Y-%m-%d") if suspended_until else None

            # 상품 삭제 체크 시
            if request.form.get('delete_products') == 'yes':
                Product.query.filter_by(seller_id=target_id).delete()
                flash('해당 유저의 상품을 삭제했습니다.')

            db.session.commit()
            flash('사용자가 차단되었습니다.')

        elif action == 'unblock':
            target_user.is_blocked = False
            target_user.suspended_until = None
            db.session.commit()
            flash('사용자 차단을 해제했습니다.')

        return redirect(url_for('admin_dashboard'))

    # 모든 사용자 조회
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/suspend', methods=['POST'])
@require_reauth
def suspend_user():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))

    user_id = request.form.get('target_id')
    
    # 자기 자신 차단 방지
    if user_id == session['user_id']:
        flash("자기 자신을 차단할 수 없습니다.")
        return redirect(url_for('admin_dashboard'))
    
    try:
        period = int(request.form.get('period_months', 1))
        if period < 1 or period > 36:
            period = 1  # 기본값 설정
    except ValueError:
        period = 1
        
    suspended_until = (datetime.now() + timedelta(days=30 * period)).strftime('%Y-%m-%d')

    # 대상 사용자 존재 확인
    user = User.query.get(user_id)
    if not user:
        flash("존재하지 않는 사용자입니다.")
        return redirect(url_for('admin_dashboard'))

    # 유저의 상품 삭제
    Product.query.filter_by(seller_id=user_id).delete()

    # 유저 계정 차단 + 휴면 처리
    user.is_blocked = True
    user.suspended_until = suspended_until
    db.session.commit()

    flash(f'유저 차단 및 상품 삭제 완료. 활동 정지 기간: {period}개월')
    return redirect(url_for('admin_dashboard'))

@app.route('/reauth', methods=['GET', 'POST'])
def reauth():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    next_url = request.args.get('next', 'dashboard')
    
    if request.method == 'POST':
        password = request.form.get('password')
        
        user = User.query.get(session['user_id'])
        
        if user and check_password_hash(user.password, password):
            # 재인증 성공, 시간 기록
            session['reauth_time'] = datetime.utcnow().isoformat()
            
            # 다음 페이지로 리다이렉트
            if next_url == 'dashboard':
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for(next_url))
        else:
            flash('비밀번호가 일치하지 않습니다.')
            
    return render_template('reauth.html', next=next_url)

@socketio.on('join_admin')
def join_admin():
    if 'user_id' not in session:
        return
        
    if session.get('username') == 'admin':
        join_room('admin')

@socketio.on('join')
def on_join(data):
    # 로그인 상태 확인
    if 'user_id' not in session:
        return
        
    room = data['room']
    # 권한 검증: 해당 방에 접근할 권한이 있는지 확인
    room_users = room.replace('room_', '').split('_')
    if session['user_id'] not in room_users and session.get('username') != 'admin':
        return
        
    join_room(room)

@socketio.on('private_message')
def on_private_message(data):
    if 'user_id' not in session:
        return

    uid = session['user_id']
    now = time.time()
    
    # ✅ 최근 10초 내 메시지 5개 이상 보낸 경우 차단
    recent = message_times[uid]
    recent.append(now)
    recent_msgs = [t for t in recent if now - t < 10]
    if len(recent_msgs) > 5:
        print(f"[RateLimit] 유저 {uid} 메시지 과도 전송 차단됨.")
        return  # 메시지 무시

    room = data['room']
    room_users = room.replace('room_', '').split('_')
    if uid not in room_users and session.get('username') != 'admin':
        return

    username = data['username']
    message = html.escape(data['message'])
    socketio.emit('private_message', {'username': username, 'message': message}, room=room)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # 경로 조작 방지를 위한 추가 검증
    if '..' in filename or filename.startswith('/'):
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@socketio.on('send_message')
def handle_send_message_event(data):
    if 'user_id' not in session:
        return

    uid = session['user_id']
    now = time.time()
    recent = message_times[uid]
    recent.append(now)
    if len([t for t in recent if now - t < 10]) > 5:
        print(f"[RateLimit] 유저 {uid} 메시지 과다 전송 차단됨.")
        return

    if 'message' in data:
        data['message'] = html.escape(data['message'])

    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

if __name__ == '__main__':
    init_db()  # 테이블 초기화를 진행
    socketio.run(app, debug=True)
