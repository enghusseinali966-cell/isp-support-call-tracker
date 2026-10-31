import os, csv, io
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-before-deploy")
db_url = os.environ.get("DATABASE_URL", "sqlite:///isp_support.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
elif db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="agent")
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class ResolutionCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(30), unique=True, nullable=False)
    title = db.Column(db.String(120), nullable=False)
    active = db.Column(db.Boolean, default=True)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subscriber = db.Column(db.String(80), nullable=False)
    issue = db.Column(db.Text, nullable=False)
    rc_id = db.Column(db.Integer, db.ForeignKey("resolution_code.id"))
    resolution = db.Column(db.Text, default="")
    status = db.Column(db.String(20), default="Open")
    agent_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    rc = db.relationship("ResolutionCode")
    agent = db.relationship("User")

def current_user():
    uid = session.get("user_id")
    return db.session.get(User, uid) if uid else None

@app.context_processor
def inject_user():
    return {"current_user": current_user()}

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        u = current_user()
        if not u: return redirect(url_for("login"))
        if u.role != "admin":
            flash("هذه الصفحة للأدمن فقط", "danger")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapped

@app.route("/")
def home():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form.get("username","").strip()).first()
        if user and user.active and user.check_password(request.form.get("password","")):
            session.clear()
            session["user_id"] = user.id
            return redirect(url_for("dashboard"))
        flash("اسم المستخدم أو كلمة المرور غير صحيحة، أو الحساب موقوف", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    q = Ticket.query if u.role == "admin" else Ticket.query.filter_by(agent_id=u.id)
    tickets = q.order_by(Ticket.created_at.desc()).limit(8).all()
    total = q.count()
    opened = q.filter_by(status="Open").count()
    closed = q.filter_by(status="Closed").count()
    unresolved = q.filter_by(status="Unresolved").count()
    agent_count = User.query.filter_by(role="agent", active=True).count() if u.role == "admin" else None
    return render_template("dashboard.html", tickets=tickets, total=total, opened=opened,
                           closed=closed, unresolved=unresolved, agent_count=agent_count)

@app.route("/tickets")
@login_required
def tickets():
    u = current_user()
    query = Ticket.query if u.role == "admin" else Ticket.query.filter_by(agent_id=u.id)
    search = request.args.get("q","").strip()
    status = request.args.get("status","")
    if search:
        query = query.filter(db.or_(Ticket.subscriber.ilike(f"%{search}%"),
                                    Ticket.issue.ilike(f"%{search}%"),
                                    Ticket.resolution.ilike(f"%{search}%")))
    if status in ("Open","Closed","Unresolved"): query = query.filter_by(status=status)
    rows = query.order_by(Ticket.created_at.desc()).all()
    return render_template("tickets.html", tickets=rows, search=search, status=status)

@app.route("/tickets/new", methods=["GET", "POST"])
@login_required
def new_ticket():
    codes = ResolutionCode.query.filter_by(active=True).order_by(ResolutionCode.code).all()
    if request.method == "POST":
        subscriber = request.form.get("subscriber","").strip()
        issue = request.form.get("issue","").strip()
        if not subscriber or not issue:
            flash("رقم المشترك ووصف المشكلة حقول إجبارية", "danger")
        else:
            rc_id = request.form.get("rc_id") or None
            rc = db.session.get(ResolutionCode, int(rc_id)) if rc_id else None
            if rc and not rc.active: rc = None
            ticket = Ticket(subscriber=subscriber, issue=issue, rc=rc,
                resolution=request.form.get("resolution","").strip(),
                status=request.form.get("status","Open") if request.form.get("status") in ("Open","Closed","Unresolved") else "Open",
                agent_id=current_user().id)
            db.session.add(ticket); db.session.commit()
            flash("تم تسجيل البلاغ بنجاح", "success")
            return redirect(url_for("tickets"))
    return render_template("ticket_form.html", codes=codes)

@app.route("/tickets/<int:ticket_id>/edit", methods=["GET", "POST"])
@login_required
def edit_ticket(ticket_id):
    t = db.session.get(Ticket, ticket_id)
    if not t: return "Not found", 404
    u = current_user()
    if u.role != "admin" and t.agent_id != u.id: return "غير مصرح", 403
    codes = ResolutionCode.query.filter_by(active=True).order_by(ResolutionCode.code).all()
    if request.method == "POST":
        t.subscriber = request.form.get("subscriber","").strip()
        t.issue = request.form.get("issue","").strip()
        rc_id = request.form.get("rc_id") or None
        t.rc = db.session.get(ResolutionCode, int(rc_id)) if rc_id else None
        t.resolution = request.form.get("resolution","").strip()
        t.status = request.form.get("status","Open") if request.form.get("status") in ("Open","Closed","Unresolved") else "Open"
        if not t.subscriber or not t.issue:
            flash("رقم المشترك ووصف المشكلة مطلوبان", "danger")
        else:
            db.session.commit(); flash("تم تحديث البلاغ", "success")
            return redirect(url_for("tickets"))
    return render_template("ticket_form.html", codes=codes, ticket=t)

@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        if len(username) < 3 or len(password) < 8:
            flash("اسم المستخدم 3 أحرف على الأقل وكلمة المرور 8 أحرف على الأقل", "danger")
        elif User.query.filter_by(username=username).first():
            flash("اسم المستخدم موجود مسبقاً", "danger")
        else:
            u = User(username=username, role="agent"); u.set_password(password)
            db.session.add(u); db.session.commit(); flash("تم إنشاء حساب Agent", "success")
        return redirect(url_for("admin_users"))
    users = User.query.order_by(User.role, User.username).all()
    return render_template("admin_users.html", users=users)

@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def toggle_user(user_id):
    u = db.session.get(User, user_id)
    if u and u.role != "admin":
        u.active = not u.active; db.session.commit()
    return redirect(url_for("admin_users"))

@app.route("/admin/codes", methods=["GET", "POST"])
@admin_required
def admin_codes():
    if request.method == "POST":
        code = request.form.get("code","").strip().upper()
        title = request.form.get("title","").strip()
        if code and title and not ResolutionCode.query.filter_by(code=code).first():
            db.session.add(ResolutionCode(code=code, title=title)); db.session.commit()
            flash("تمت إضافة رمز الحل", "success")
        else: flash("تأكد من البيانات وأن الرمز غير مكرر", "danger")
        return redirect(url_for("admin_codes"))
    codes = ResolutionCode.query.order_by(ResolutionCode.code).all()
    return render_template("admin_codes.html", codes=codes)

@app.route("/admin/codes/<int:code_id>/toggle", methods=["POST"])
@admin_required
def toggle_code(code_id):
    c = db.session.get(ResolutionCode, code_id)
    if c: c.active = not c.active; db.session.commit()
    return redirect(url_for("admin_codes"))

@app.route("/export.csv")
@login_required
def export_csv():
    u = current_user()
    q = Ticket.query if u.role == "admin" else Ticket.query.filter_by(agent_id=u.id)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Subscriber","Issue","RC","Resolution","Status","Agent","Created At"])
    for t in q.order_by(Ticket.created_at.desc()).all():
        writer.writerow([t.id,t.subscriber,t.issue,t.rc.code if t.rc else "",t.resolution,t.status,t.agent.username,t.created_at.isoformat()])
    resp = make_response("\ufeff" + output.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=isp-support-tickets.csv"
    return resp

@app.cli.command("init-db")
def init_db():
    db.create_all()
    admin_name = os.environ.get("ADMIN_USERNAME")
    admin_pass = os.environ.get("ADMIN_PASSWORD")
    if admin_name and admin_pass and not User.query.filter_by(username=admin_name).first():
        admin = User(username=admin_name, role="admin")
        admin.set_password(admin_pass)
        db.session.add(admin); db.session.commit()
        print("Admin account created.")
    else:
        print("Tables ready. Set ADMIN_USERNAME and ADMIN_PASSWORD to create the first admin.")

@app.route("/health")
def health():
    return {"status":"ok"}

# Initialize schema and first admin automatically on deployment.
with app.app_context():
    db.create_all()
    admin_name = os.environ.get("ADMIN_USERNAME")
    admin_pass = os.environ.get("ADMIN_PASSWORD")
    if admin_name and admin_pass and not User.query.filter_by(username=admin_name).first():
        admin = User(username=admin_name, role="admin")
        admin.set_password(admin_pass)
        db.session.add(admin)
        db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
