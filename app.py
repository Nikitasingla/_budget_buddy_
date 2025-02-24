from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, UserMixin, login_required, current_user
from datetime import datetime
from sqlalchemy import func
from functools import wraps

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SECRET_KEY"] = "welcome"

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(100), default="user")
    expenses = db.relationship('Expense', backref='user', lazy=True)
    income = db.relationship('Income', backref='user', lazy=True)

    # Save hashed password
    def save_hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Verify password hash
    def check_hash_password(self, password):
        return check_password_hash(self.password_hash, password)


class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    payment_mode = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


class Income(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    source = db.Column(db.String(50), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class Limit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/AboutUs")
def about():
    return render_template("AboutUs.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if User.query.filter_by(email=email).first():
            flash("User Already Exists", "danger")
            return redirect(url_for("login"))

        user_data = User(username=username, email=email)
        user_data.save_hash_password(password)

        db.session.add(user_data)
        db.session.commit()
        flash("User Registered Successfully", "success")
        return redirect(url_for("login"))

    return render_template("signup.html",action="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user_data = User.query.filter_by(email=email).first()

        if user_data and user_data.check_hash_password(password):
            login_user(user_data)
            flash("User Logged In Successfully", "success")

            if user_data.role=="admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("home"))

        flash("Invalid Email or Password", "danger")
        return redirect(url_for("login"))
    return render_template("signup.html")

@app.route('/profile')
@login_required
def profile():
    expenses = Expense.query.filter_by(user_id=current_user.id).all()
    incomes = Income.query.filter_by(user_id=current_user.id).all()
    total_expense = sum(expense.amount for expense in expenses)
    total_income = sum(income.amount for income in incomes)
    return render_template('profile.html',expenses=expenses,
                           incomes=incomes,
                           total_expense=total_expense,
                           total_income=total_income)

@app.route('/set_limit', methods=['GET', 'POST'])
@login_required
def set_limit():
    if request.method == 'POST':
        category = request.form.get('category')
        amount = float(request.form.get('amount'))

        existing_limit = Limit.query.filter_by(user_id=current_user.id, category=category).first()

        if existing_limit:
            existing_limit.amount = amount
        else:
            new_limit = Limit(category=category, amount=amount, user_id=current_user.id)
            db.session.add(new_limit)

        db.session.commit()
        flash('Limit Set Successfully!', 'success')
        return redirect(url_for('set_limit'))

    limits = Limit.query.filter_by(user_id=current_user.id).all()
    return render_template('add_limit.html', limits=limits)


# @app.route('/dashboard')
# @login_required
# def dashboard():
#     expenses = Expense.query.filter_by(user_id=current_user.id).all()
#     incomes = Income.query.filter_by(user_id=current_user.id).all()
#     total_expense = sum(expense.amount for expense in expenses)
#     total_income = sum(income.amount for income in incomes)
#     return render_template('dashboard.html',
#                            expenses=expenses,
#                            incomes=incomes,
#                            total_expense=total_expense,
#                            total_income=total_income)

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     total_income = db.session.query(func.sum(Income.amount)).scalar() or 0
#     total_expense = db.session.query(func.sum(Expense.amount)).scalar() or 0
#     total_transactions = Expense.query.count() + Income.query.count()  # <-- Added this line

#     return render_template('dashboard.html', total_income=total_income, 
#                            total_expense=total_expense, 
#                            total_transactions=total_transactions)

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     total_income = db.session.query(func.sum(Income.amount)).filter_by(user_id=current_user.id).scalar() or 0
#     total_expense = db.session.query(func.sum(Expense.amount)).filter_by(user_id=current_user.id).scalar() or 0
#     total_transactions = Expense.query.filter_by(user_id=current_user.id).count() + Income.query.filter_by(user_id=current_user.id).count()

#     return render_template('dashboard.html', total_income=total_income, 
#                            total_expense=total_expense, 
#                            total_transactions=total_transactions)

@app.route('/dashboard')
@login_required
def dashboard():
    total_income = db.session.query(func.sum(Income.amount)).filter_by(user_id=current_user.id).scalar() or 0
    total_expense = db.session.query(func.sum(Expense.amount)).filter_by(user_id=current_user.id).scalar() or 0
    total_transactions = Expense.query.filter_by(user_id=current_user.id).count() + Income.query.filter_by(user_id=current_user.id).count()

    limits = Limit.query.filter_by(user_id=current_user.id).all()

    return render_template('dashboard.html', 
                           total_income=total_income, 
                           total_expense=total_expense, 
                           total_transactions=total_transactions,
                           limits=limits)


# @app.route('/expense/add', methods=['GET', 'POST'])
# @login_required
# def add_expense():
#     if request.method == 'POST':
#         expense = Expense(
#             amount=float(request.form.get('amount')),
#             category=request.form.get('category'),
#             description=request.form.get('description'),
#             payment_mode=request.form.get('payment_mode'),
#             user_id=current_user.id
#         )
#         db.session.add(expense)
#         db.session.commit()

#         monthly_income = sum(income.amount for income in Income.query.filter_by(user_id=current_user.id).all())
#         if monthly_income > 0 and expense.amount > (monthly_income * 0.8):
#             flash('Warning: This expense exceeds 80% of your monthly income!', 'warning')

#         return redirect(url_for('dashboard'))
#     return render_template('add_expense.html')

@app.route('/expense/add', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        amount = float(request.form.get('amount'))
        category = request.form.get('category')

        # ✅ Check if limit is set for this category
        limit = Limit.query.filter_by(user_id=current_user.id, category=category).first()

        if limit and amount > limit.amount:
            flash(f'Warning: Your {category} expense exceeded the set limit of ₹{limit.amount}!', 'warning')

        # ✅ Add the expense after checking
        expense = Expense(
            amount=amount,
            category=category,
            description=request.form.get('description'),
            payment_mode=request.form.get('payment_mode'),
            user_id=current_user.id
        )
        db.session.add(expense)
        db.session.commit()

        return redirect(url_for('dashboard'))
    return render_template('add_expense.html')


@app.route("/expense")
def expense():
    expenses = Expense.query.filter_by(user_id=current_user.id).all()
    return render_template("expense.html" , expenses=expenses)


@app.route('/income/add', methods=['GET', 'POST'])
@login_required
def add_income():
    if request.method == 'POST':
        income = Income(
            amount=float(request.form.get('amount')),
            source=request.form.get('source'),
            user_id=current_user.id
        )
        db.session.add(income)
        db.session.commit()
        return redirect(url_for('income'))
    return render_template('add_income.html')

@app.route("/income")
def income():
    incomes= Income.query.filter_by(user_id=current_user.id).all()
    # print(incomes)
    return render_template("income.html" ,incomes=incomes )


@app.route('/income/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_income(id):
    income = Income.query.get_or_404(id)
    if request.method == 'POST':
        income.amount = float(request.form.get('amount'))
        income.source = request.form.get('source')
        # expense.category = request.form.get('category')
        # expense.description = request.form.get('description')
        # expense.payment_mode = request.form.get('payment_mode')
        db.session.commit()
        return redirect(url_for('income'))
    return render_template('edit_income.html', income=income)


@app.route('/income/<int:id>/delete')
@login_required
def delete_income(id):
    income = Income.query.get_or_404(id)
    db.session.delete(income)
    db.session.commit()
    return redirect(url_for('add_income'))



#expense


@app.route('/expense/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_expense(id):
    expense = Expense.query.get_or_404(id)
    if request.method == 'POST':
        expense.amount = float(request.form.get('amount'))
        expense.category = request.form.get('category')
        expense.description = request.form.get('description')
        expense.payment_mode = request.form.get('payment_mode')
        db.session.commit()
        return redirect(url_for('expense'))
    return render_template('edit_expense.html', expense=expense)


@app.route('/expense/<int:id>/delete')
@login_required
def delete_expense(id):
    expense = Expense.query.get_or_404(id)
    db.session.delete(expense)
    db.session.commit()
    return redirect(url_for('add_expense'))



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("User logged out successfully", "info")
    return redirect(url_for('home'))


def role_required(role):
    def decorator(func):
        @wraps(func)
        def wrap(*args, **kwargs):
            if current_user.role != role:
                flash("Unauthorized Access", "danger")
                return redirect(url_for("dashboard"))
            return func(*args, **kwargs)
        return wrap
    return decorator


# @app.route("/admin")
# @login_required
# def admin():
#     # Check if user is admin
#     if current_user.role != "admin":
#         flash("You are not authorized to access admin panel", "error")
#         return redirect(url_for("dashboard"))
    
#     # Get all users and their details
#     users = User.query.all()
#     user_details = []
    
#     for user in users:
#         # Get user's expenses and income
#         expenses = Expense.query.filter_by(user_id=user.id).all()
#         incomes = Income.query.filter_by(user_id=user.id).all()
        
#         # Calculate totals
#         total_expense = sum(expense.amount for expense in expenses)
#         total_income = sum(income.amount for income in incomes)
        
#         user_details.append({
#             'user': user,
#             'total_expenses': total_expense,
#             'total_income': total_income,
#             'expense_count': len(expenses),
#             'income_count': len(incomes)
#         })
    
#     return render_template("admin.html", user_details=user_details)

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != "admin":  # Sirf admin ko access mile
        flash("Access Denied! You are not an admin.", "danger")
        return redirect(url_for('dashboard'))
    
    users = User.query.all()  # Sabhi users fetch kar raha hai
    return render_template('admin.html', users=users)


with app.app_context():
    db.create_all()

    if not User.query.filter_by(role="admin").first():
        admin = User(username="vaibhav", email="vaibhav@gmail.com", role="admin")
        admin.save_hash_password("admin")
        db.session.add(admin)
        db.session.commit()


if __name__ == "__main__":
    app.run(debug=True)
