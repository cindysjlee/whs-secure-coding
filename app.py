import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
import time

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort, send_from_directory
from flask_socketio import SocketIO, send, disconnect, emit

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from flask_wtf.csrf import CSRFProtect

import io
from pathlib import Path

from PIL import Image, UnidentifiedImageError

load_dotenv()
password_hasher = PasswordHasher()

app = Flask(__name__)

# SECRET_KEY는 소스 코드에 저장하지 않고 환경변수에서 읽는다.
secret_key = os.getenv("SECRET_KEY")
if not secret_key:
    raise RuntimeError(
        "SECRET_KEY가 설정되지 않았습니다. "
        ".env.example을 참고하여 .env 파일을 생성하세요."
    )

app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

UPLOAD_DIR = Path(app.root_path) / 'uploads' / 'products'
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

csrf = CSRFProtect(app)
DATABASE = "market.db"

socketio = SocketIO(app)

chat_rate_limits = {}

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
        db.execute("PRAGMA foreign_keys = ON")
    return db

def write_audit_log(
    action,
    actor_id=None,
    target_type=None,
    target_id=None,
    detail=None
):
    db = get_db()

    db.execute(
        """
        INSERT INTO audit_log
            (id, actor_id, action, target_type, target_id, detail)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            actor_id,
            action,
            target_type,
            target_id,
            detail
        )
    )


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )

    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    return response

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # 사용자
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT NOT NULL DEFAULT '',
                balance INTEGER NOT NULL DEFAULT 10000
                    CHECK (balance >= 0),
                role TEXT NOT NULL DEFAULT 'user'
                    CHECK (role IN ('user', 'admin')),
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'suspended')),
                failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT
            )
        """)

        # 상품
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price INTEGER NOT NULL
                    CHECK (price >= 0 AND price <= 100000000),
                seller_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'blocked')),
                image_filename TEXT,
                FOREIGN KEY (seller_id)
                    REFERENCES user(id)
                    ON DELETE CASCADE
            )
        """)

        # 신고
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_type TEXT NOT NULL
                    CHECK (target_type IN ('user', 'product')),
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'resolved')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (reporter_id)
                    REFERENCES user(id)
                    ON DELETE CASCADE,

                UNIQUE (reporter_id, target_type, target_id)
            )
        """)

        # 채팅
        # receiver_id가 NULL이면 전체 채팅,
        # 값이 존재하면 해당 사용자와의 1:1 채팅으로 사용한다.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS message (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (sender_id)
                    REFERENCES user(id)
                    ON DELETE CASCADE,

                FOREIGN KEY (receiver_id)
                    REFERENCES user(id)
                    ON DELETE CASCADE
            )
        """)

        # 송금
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transfer (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL CHECK (amount > 0),
                idempotency_key TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (sender_id)
                    REFERENCES user(id),

                FOREIGN KEY (receiver_id)
                    REFERENCES user(id),

                CHECK (sender_id <> receiver_id)
            )
        """)

        # 보안상 중요한 행위를 기록
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                actor_id TEXT,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id TEXT,
                detail TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (actor_id)
                    REFERENCES user(id)
            )
        """)

        db.commit()

def is_valid_password(password):
    if len(password) < 10:
        return False

    if not any(char.isalpha() for char in password):
        return False

    if not any(char.isdigit() for char in password):
        return False

    return True

def utc_now():
    return datetime.now(timezone.utc)


def parse_db_time(value):
    if not value:
        return None

    return datetime.fromisoformat(value)

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # 사용자명 검증
        if not (3 <= len(username) <= 30):
            flash('사용자명은 3자 이상 30자 이하로 입력해주세요.')
            return redirect(url_for('register'))

        # 비밀번호 정책 검증
        if not is_valid_password(password):
            flash('비밀번호는 10자 이상이며 영문과 숫자를 포함해야 합니다.')
            return redirect(url_for('register'))

        db = get_db()
        cursor = db.cursor()

        # 중복 사용자 확인
        cursor.execute(
            "SELECT id FROM user WHERE username = ?",
            (username,)
        )

        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())

        # 평문 비밀번호를 Argon2id로 해싱
        password_hash = password_hasher.hash(password)

        cursor.execute(
            """
            INSERT INTO user (id, username, password)
            VALUES (?, ?, ?)
            """,
            (user_id, username, password_hash)
        )

        write_audit_log(
            action='REGISTER',
            actor_id=user_id,
            target_type='user',
            target_id=user_id
        )

        db.commit()

        flash('회원가입이 완료되었습니다. 로그인해주세요.')
        return redirect(url_for('login'))

    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        db = get_db()
        cursor = db.cursor()

        # 비밀번호를 SQL에서 직접 비교하지 않는다.
        cursor.execute(
            "SELECT * FROM user WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()

        # 존재하지 않는 계정도 구체적인 이유를 알려주지 않는다.
        if user is None:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

        # 정지된 계정 확인
        if user['status'] == 'suspended':
            flash('현재 사용할 수 없는 계정입니다.')
            return redirect(url_for('login'))

        # 로그인 잠금 상태 확인
        locked_until = parse_db_time(user['locked_until'])

        if locked_until and utc_now() < locked_until:
            flash('로그인 시도가 일시적으로 제한되었습니다. 잠시 후 다시 시도해주세요.')
            return redirect(url_for('login'))

        try:
            password_hasher.verify(user['password'], password)
            password_correct = True
        except VerifyMismatchError:
            password_correct = False
        except Exception:
            # 손상되거나 예상하지 못한 형식의 해시도 인증 실패로 처리
            password_correct = False

        if not password_correct:
            failed_attempts = user['failed_login_attempts'] + 1

            if failed_attempts >= 5:
                lock_until = utc_now() + timedelta(minutes=15)

                cursor.execute(
                    """
                    UPDATE user
                    SET failed_login_attempts = 0,
                        locked_until = ?
                    WHERE id = ?
                    """,
                    (lock_until.isoformat(), user['id'])
                )
            else:
                cursor.execute(
                    """
                    UPDATE user
                    SET failed_login_attempts = ?
                    WHERE id = ?
                    """,
                    (failed_attempts, user['id'])
                )

            if failed_attempts >= 5:
                write_audit_log(
                    action='ACCOUNT_LOCKED',
                    actor_id=user['id'],
                    target_type='user',
                    target_id=user['id'],
                    detail='15 minutes'
                )
            else:
                write_audit_log(
                    action='LOGIN_FAILED',
                    actor_id=user['id'],
                    target_type='user',
                    target_id=user['id'],
                    detail=f'failed_attempts={failed_attempts}'
                )

            db.commit()

            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

        # 로그인 성공 시 기존 실패 기록 제거
        cursor.execute(
            """
            UPDATE user
            SET failed_login_attempts = 0,
                locked_until = NULL
            WHERE id = ?
            """,
            (user['id'],)
        )

        write_audit_log(
            action='LOGIN_SUCCESS',
            actor_id=user['id'],
            target_type='user',
            target_id=user['id']
        )

        db.commit()

        # 기존 세션 데이터를 제거한 뒤 새 인증 상태 설정
        session.clear()
        session['user_id'] = user['id']
        session.permanent = True

        flash('로그인 성공!')
        return redirect(url_for('dashboard'))

    return render_template('login.html')

# 로그아웃
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    # 로그인하지 않은 사용자는 로그인 페이지로 이동
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 로그인한 사용자 정보 조회
    cursor.execute(
        """
        SELECT *
        FROM user
        WHERE id = ?
        """,
        (session['user_id'],)
    )
    current_user = cursor.fetchone()

    # 전체 상품 조회
    cursor.execute(
        """
        SELECT *
        FROM product
        ORDER BY rowid DESC
        """
    )
    all_products = cursor.fetchall()

    # 전체 채팅에서 최근 10개 메시지만 조회
    #
    # created_at은 초 단위라 짧은 시간에 여러 메시지가 저장되면
    # 같은 시간이 기록될 수 있다.
    # 따라서 현재 SQLite 환경에서는 rowid를 이용해
    # 실제 INSERT 순서를 기준으로 최근 메시지를 가져온다.
    cursor.execute(
        """
        SELECT
            message.id,
            message.content,
            message.created_at,
            user.username
        FROM message
        JOIN user
            ON message.sender_id = user.id
        WHERE message.receiver_id IS NULL
        ORDER BY message.rowid DESC
        LIMIT 10
        """
    )

    chat_messages = cursor.fetchall()

    # DB에서는 최신 메시지부터 10개를 가져왔으므로
    # 화면에서는 오래된 메시지 → 최신 메시지 순으로 다시 뒤집는다.
    chat_messages = list(reversed(chat_messages))

    return render_template(
        'dashboard.html',
        products=all_products,
        user=current_user,
        chat_messages=chat_messages
    )

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        "SELECT * FROM user WHERE id = ?",
        (session['user_id'],)
    )
    current_user = cursor.fetchone()

    if current_user is None:
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form.get('action')

        # 프로필 소개 수정
        if action == 'update_bio':
            bio = request.form.get('bio', '').strip()

            if len(bio) > 500:
                flash('소개는 500자 이하로 입력해주세요.')
                return redirect(url_for('profile'))

            cursor.execute(
                "UPDATE user SET bio = ? WHERE id = ?",
                (bio, session['user_id'])
            )
            db.commit()

            flash('프로필이 업데이트되었습니다.')
            return redirect(url_for('profile'))

        # 비밀번호 변경
        if action == 'change_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')

            # 새 비밀번호 확인값 비교
            if new_password != confirm_password:
                flash('새 비밀번호가 서로 일치하지 않습니다.')
                return redirect(url_for('profile'))

            # 기존과 동일한 비밀번호 정책 적용
            if not is_valid_password(new_password):
                flash('새 비밀번호는 10자 이상이며 영문과 숫자를 포함해야 합니다.')
                return redirect(url_for('profile'))

            # 현재 비밀번호 확인
            try:
                password_hasher.verify(
                    current_user['password'],
                    current_password
                )
            except VerifyMismatchError:
                flash('현재 비밀번호가 올바르지 않습니다.')
                return redirect(url_for('profile'))
            except Exception:
                flash('비밀번호를 확인할 수 없습니다.')
                return redirect(url_for('profile'))

            # 현재 비밀번호와 새 비밀번호가 같은지 방지
            try:
                if password_hasher.verify(
                    current_user['password'],
                    new_password
                ):
                    flash('현재 비밀번호와 다른 비밀번호를 사용해주세요.')
                    return redirect(url_for('profile'))
            except VerifyMismatchError:
                pass

            # 새 비밀번호를 Argon2id로 해싱
            new_password_hash = password_hasher.hash(new_password)

            cursor.execute(
                "UPDATE user SET password = ? WHERE id = ?",
                (new_password_hash, session['user_id'])
            )
            db.commit()

            # 비밀번호 변경 후 다시 로그인하도록 세션 제거
            session.clear()

            flash('비밀번호가 변경되었습니다. 새 비밀번호로 다시 로그인해주세요.')
            return redirect(url_for('login'))

        flash('잘못된 요청입니다.')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=current_user)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        receiver_id = request.form.get('receiver_id', '').strip()
        amount_raw = request.form.get('amount', '').strip()
        idempotency_key = request.form.get('idempotency_key', '').strip()

        # 송금액을 정수로 변환
        try:
            amount = int(amount_raw)
        except ValueError:
            flash('송금액은 숫자로 입력해주세요.')
            return redirect(url_for('transfer'))

        # 0원 및 음수 송금 차단
        if amount <= 0:
            flash('송금액은 1원 이상이어야 합니다.')
            return redirect(url_for('transfer'))

        # 과도한 금액 입력 제한
        if amount > 100_000_000:
            flash('한 번에 송금할 수 있는 금액을 초과했습니다.')
            return redirect(url_for('transfer'))

        # 자기 자신에게 송금 차단
        if receiver_id == session['user_id']:
            flash('자기 자신에게는 송금할 수 없습니다.')
            return redirect(url_for('transfer'))

        # 수신자가 실제 존재하는지 확인
        cursor.execute(
            "SELECT id FROM user WHERE id = ?",
            (receiver_id,)
        )
        receiver = cursor.fetchone()

        if receiver is None:
            flash('존재하지 않는 사용자입니다.')
            return redirect(url_for('transfer'))

        # 멱등 키가 없으면 요청 거부
        if not idempotency_key:
            flash('올바르지 않은 송금 요청입니다.')
            return redirect(url_for('transfer'))

        try:
            # 현재 잔액이 충분할 때만 차감
            cursor.execute(
                """
                UPDATE user
                SET balance = balance - ?
                WHERE id = ?
                  AND balance >= ?
                """,
                (
                    amount,
                    session['user_id'],
                    amount
                )
            )

            # 실제로 한 행이 수정됐는지 확인
            if cursor.rowcount != 1:
                db.rollback()
                flash('잔액이 부족합니다.')
                return redirect(url_for('transfer'))

            # 수신자 잔액 증가
            cursor.execute(
                """
                UPDATE user
                SET balance = balance + ?
                WHERE id = ?
                """,
                (
                    amount,
                    receiver_id
                )
            )

            # 송금 내역 저장
            transfer_id = str(uuid.uuid4())

            cursor.execute(
                """
                INSERT INTO transfer
                    (
                        id,
                        sender_id,
                        receiver_id,
                        amount,
                        idempotency_key
                    )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    transfer_id,
                    session['user_id'],
                    receiver_id,
                    amount,
                    idempotency_key
                )
            )

            write_audit_log(
                action='TRANSFER',
                actor_id=session['user_id'],
                target_type='user',
                target_id=receiver_id,
                detail=f'amount={amount}, transfer_id={transfer_id}'
            )

            db.commit()

        except sqlite3.IntegrityError:
            db.rollback()
            flash('이미 처리된 송금 요청이거나 올바르지 않은 요청입니다.')
            return redirect(url_for('transfer'))

        flash(f'{amount:,}원이 송금되었습니다.')
        return redirect(url_for('transfer'))

    # 현재 사용자 정보
    cursor.execute(
        "SELECT id, username, balance FROM user WHERE id = ?",
        (session['user_id'],)
    )
    current_user = cursor.fetchone()

    # 나를 제외한 송금 가능 사용자
    cursor.execute(
        """
        SELECT id, username
        FROM user
        WHERE id != ?
          AND status = 'active'
        ORDER BY username
        """,
        (session['user_id'],)
    )
    users = cursor.fetchall()

    # GET 요청마다 새로운 멱등 키 생성
    idempotency_key = str(uuid.uuid4())

    return render_template(
        'transfer.html',
        user=current_user,
        users=users,
        idempotency_key=idempotency_key
    )

def save_product_image(file):
    if not file or not file.filename:
        return None

    raw = file.read()

    if len(raw) > 4 * 1024 * 1024:
        raise ValueError('이미지 파일은 4MB 이하여야 합니다.')

    try:
        image = Image.open(io.BytesIO(raw))
        image.load()
    except (UnidentifiedImageError, OSError):
        raise ValueError('올바른 이미지 파일이 아닙니다.')

    if image.width < 1 or image.height < 1:
        raise ValueError('올바르지 않은 이미지입니다.')

    if image.width > 5000 or image.height > 5000:
        raise ValueError('이미지 해상도가 너무 큽니다.')

    if image.mode != 'RGB':
        if 'A' in image.getbands():
            background = Image.new('RGB', image.size, 'white')
            background.paste(image, mask=image.getchannel('A'))
            image = background
        else:
            image = image.convert('RGB')

    filename = f'{uuid.uuid4().hex}.jpg'
    save_path = UPLOAD_DIR / filename

    image.save(
        save_path,
        format='JPEG',
        quality=85,
        optimize=True
    )

    return filename

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price_raw = request.form.get('price', '').strip()
        image_file = request.files.get('image')

        if not (1 <= len(title) <= 100):
            flash('상품명은 1자 이상 100자 이하로 입력해주세요.')
            return redirect(url_for('new_product'))

        if not (1 <= len(description) <= 2000):
            flash('상품 설명은 1자 이상 2000자 이하로 입력해주세요.')
            return redirect(url_for('new_product'))

        try:
            price = int(price_raw)
        except ValueError:
            flash('가격은 숫자로 입력해주세요.')
            return redirect(url_for('new_product'))

        if not (0 <= price <= 100_000_000):
            flash('가격은 0원 이상 1억원 이하로 입력해주세요.')
            return redirect(url_for('new_product'))

        image_filename = None

        if image_file and image_file.filename:
            try:
                image_filename = save_product_image(image_file)
            except ValueError as e:
                flash(str(e))
                return redirect(url_for('new_product'))

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())

        try:
            cursor.execute(
                """
                INSERT INTO product
                    (id, title, description, price, seller_id, image_filename)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    product_id,
                    title,
                    description,
                    price,
                    session['user_id'],
                    image_filename
                )
            )

            write_audit_log(
                action='PRODUCT_CREATE',
                actor_id=session['user_id'],
                target_type='product',
                target_id=product_id,
                detail=f'price={price}'
            )

            db.commit()

        except sqlite3.Error:
            db.rollback()

            if image_filename:
                image_path = UPLOAD_DIR / image_filename
                image_path.unlink(missing_ok=True)

            flash('상품 등록 중 오류가 발생했습니다.')
            return redirect(url_for('new_product'))

        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('new_product.html')

@app.route('/uploads/products/<filename>')
def product_image(filename):
    if not filename.endswith('.jpg'):
        abort(404)

    if len(filename) != 36:
        abort(404)

    return send_from_directory(
        UPLOAD_DIR,
        filename
    )

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
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
    return render_template('view_product.html', product=product, seller=seller)

@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        "SELECT * FROM product WHERE id = ?",
        (product_id,)
    )
    product = cursor.fetchone()

    if product is None:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 핵심: 상품 소유자 확인
    if product['seller_id'] != session['user_id']:
        flash('해당 상품을 수정할 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price_raw = request.form.get('price', '').strip()

        if not (1 <= len(title) <= 100):
            flash('상품명은 1자 이상 100자 이하로 입력해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))

        if not (1 <= len(description) <= 2000):
            flash('상품 설명은 1자 이상 2000자 이하로 입력해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))

        try:
            price = int(price_raw)
        except ValueError:
            flash('가격은 숫자로 입력해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))

        if not (0 <= price <= 100_000_000):
            flash('가격은 0원 이상 1억원 이하로 입력해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))

        cursor.execute(
            """
            UPDATE product
            SET title = ?, description = ?, price = ?
            WHERE id = ?
            """,
            (title, description, price, product_id)
        )

        write_audit_log(
            action='PRODUCT_UPDATE',
            actor_id=session['user_id'],
            target_type='product',
            target_id=product_id,
            detail=f'price={price}'
        )
        
        db.commit()

        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    return render_template('edit_product.html', product=product)

@app.route('/product/<product_id>/delete', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        "SELECT * FROM product WHERE id = ?",
        (product_id,)
    )
    product = cursor.fetchone()

    if product is None:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 상품 소유자만 삭제 가능
    if product['seller_id'] != session['user_id']:
        flash('해당 상품을 삭제할 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    image_filename = product['image_filename']

    try:
        cursor.execute(
            "DELETE FROM product WHERE id = ?",
            (product_id,)
        )

        write_audit_log(
            action='PRODUCT_DELETE',
            actor_id=session['user_id'],
            target_type='product',
            target_id=product_id
        )

        db.commit()

    except sqlite3.Error:
        db.rollback()
        flash('상품 삭제 중 오류가 발생했습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    if image_filename:
        image_path = UPLOAD_DIR / image_filename

        try:
            image_path.unlink(missing_ok=True)
        except OSError:
            pass

    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        target_type = request.form.get('target_type', '').strip()
        target_id = request.form.get('target_id', '').strip()
        reason = request.form.get('reason', '').strip()

        # 신고 유형 검증
        if target_type not in ('user', 'product'):
            flash('올바르지 않은 신고 유형입니다.')
            return redirect(url_for('report'))

        # 신고 사유 검증
        if not (1 <= len(reason) <= 500):
            flash('신고 사유는 1자 이상 500자 이하로 입력해주세요.')
            return redirect(url_for('report'))

        # 사용자 신고
        if target_type == 'user':
            if target_id == session['user_id']:
                flash('자기 자신은 신고할 수 없습니다.')
                return redirect(url_for('report'))

            cursor.execute(
                "SELECT id FROM user WHERE id = ?",
                (target_id,)
            )

            if cursor.fetchone() is None:
                flash('존재하지 않는 사용자입니다.')
                return redirect(url_for('report'))

        # 상품 신고
        elif target_type == 'product':
            cursor.execute(
                "SELECT id, seller_id FROM product WHERE id = ?",
                (target_id,)
            )
            target_product = cursor.fetchone()

            if target_product is None:
                flash('존재하지 않는 상품입니다.')
                return redirect(url_for('report'))

            if target_product['seller_id'] == session['user_id']:
                flash('자신의 상품은 신고할 수 없습니다.')
                return redirect(url_for('report'))

        # 이미 신고한 대상인지 확인
        cursor.execute(
            """
            SELECT id
            FROM report
            WHERE reporter_id = ?
              AND target_type = ?
              AND target_id = ?
            """,
            (
                session['user_id'],
                target_type,
                target_id
            )
        )

        if cursor.fetchone() is not None:
            flash('이미 신고한 대상입니다.')
            return redirect(url_for('report'))

        report_id = str(uuid.uuid4())

        try:
            cursor.execute(
                """
                INSERT INTO report
                    (id, reporter_id, target_type, target_id, reason)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    session['user_id'],
                    target_type,
                    target_id,
                    reason
                )
            )

            write_audit_log(
                action='REPORT_CREATE',
                actor_id=session['user_id'],
                target_type=target_type,
                target_id=target_id,
                detail=f'report_id={report_id}'
            )

            db.commit()

        except sqlite3.IntegrityError:
            db.rollback()
            flash('신고를 처리할 수 없습니다.')
            return redirect(url_for('report'))

        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    # 신고 페이지에 보여줄 사용자 목록
    cursor.execute(
        """
        SELECT id, username
        FROM user
        WHERE id != ?
        ORDER BY username
        """,
        (session['user_id'],)
    )
    users = cursor.fetchall()

    # 자신의 상품을 제외한 상품 목록
    cursor.execute(
        """
        SELECT id, title
        FROM product
        WHERE seller_id != ?
        ORDER BY title
        """,
        (session['user_id'],)
    )
    products = cursor.fetchall()

    return render_template(
        'report.html',
        users=users,
        products=products
    )

@socketio.on('connect')
def handle_connect():
    # 로그인하지 않은 사용자의 Socket.IO 연결 거부
    if 'user_id' not in session:
        return False

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        """
        SELECT id
        FROM user
        WHERE id = ?
          AND status = 'active'
        """,
        (session['user_id'],)
    )

    if cursor.fetchone() is None:
        return False


@socketio.on('send_message')
def handle_send_message_event(data):
    # 혹시 연결 이후 세션이 유효하지 않게 된 경우 다시 확인
    if 'user_id' not in session:
        disconnect()
        return

    # 예상하지 않은 데이터 형식 차단
    if not isinstance(data, dict):
        return

    message = str(data.get('message', '')).strip()

    # 빈 메시지 차단
    if not message:
        return

    # 과도하게 긴 메시지 차단
    if len(message) > 500:
        return
    
    # 사용자별 채팅 속도 제한
    # 10초 동안 최대 5개 허용.
    # 초과하면 10초 동안 채팅을 차단한다.
    user_id = session['user_id']
    now = time.monotonic()

    rate_info = chat_rate_limits.get(
        user_id,
        {
            'timestamps': [],
            'blocked_until': 0
        }
    )

    # 현재 차단 상태인지 확인
    if now < rate_info['blocked_until']:
        remaining = int(rate_info['blocked_until'] - now) + 1

        emit(
            'chat_error',
            {
                'message':
                    f'채팅 도배가 감지되었습니다. '
                    f'{remaining}초 후 다시 시도해주세요.'
            }
        )
        return

    # 최근 10초 이내 전송 기록만 유지
    rate_info['timestamps'] = [
        timestamp
        for timestamp in rate_info['timestamps']
        if now - timestamp < 10
    ]

    # 이미 5개의 메시지를 보낸 상태라면
    # 현재 시점부터 10초간 차단
    if len(rate_info['timestamps']) >= 5:
        rate_info['blocked_until'] = now + 10

        # 차단 상태 저장
        chat_rate_limits[user_id] = rate_info

        emit(
            'chat_error',
            {
                'message':
                    '채팅 도배가 감지되었습니다. '
                    '10초 동안 메시지를 보낼 수 없습니다.'
            }
        )
        return

    # 정상 메시지 전송 기록
    rate_info['timestamps'].append(now)
    chat_rate_limits[user_id] = rate_info

    db = get_db()
    cursor = db.cursor()

    # 발신자는 클라이언트가 아니라 세션을 기준으로 서버가 결정
    cursor.execute(
        """
        SELECT id, username
        FROM user
        WHERE id = ?
          AND status = 'active'
        """,
        (session['user_id'],)
    )
    user = cursor.fetchone()

    if user is None:
        disconnect()
        return

    message_id = str(uuid.uuid4())

    try:
        cursor.execute(
            """
            INSERT INTO message
                (id, sender_id, receiver_id, content)
            VALUES (?, ?, NULL, ?)
            """,
            (
                message_id,
                user['id'],
                message
            )
        )

        db.commit()

    except sqlite3.IntegrityError:
        db.rollback()
        return

    send(
        {
            'message_id': message_id,
            'username': user['username'],
            'message': message
        },
        broadcast=True
    )

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    socketio.run(app, debug=debug_mode)
