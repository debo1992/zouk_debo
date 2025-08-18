from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for flashing messages
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)
PLAN_CREDITS = {
    "Zouk Lover": 12,       # up to 12 classes in 4 weeks
    "Zouk Fan": 12,         # 12 classes, flexible 8 weeks
    "Zouk Admirer": 6,      # 6 classes
    "Casual Drop In": 1,    # 1 class
}


users = {}

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')  # ← This must match your filename exactly

@app.route('/about')
def about():
    return render_template('about.html')


class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    plan_name = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('purchases', lazy=True))


# Define User table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    remaining_classes = db.Column(db.Integer, default=0)

# Create DB tables if they don't exist
with app.app_context():
    db.create_all()

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            flash('Passwords do not match!')
            return redirect(url_for('signup'))

        # Check if user exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered!')
            return redirect(url_for('signup'))

        # Create and save new user
        hashed_pw = generate_password_hash(password)
        new_user = User(name=name, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        flash('Signup successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.name
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please log in first.')
        return redirect(url_for('login'))

    # Example check by email or username:
    admin_email = "debo_da_zouker"
    is_admin = (session.get('username') == admin_email)

    if is_admin:
        users = User.query.order_by(User.id).all()
        return render_template('dashboard.html', username=session['username'], users=users, is_admin=True)
    else:
        user = User.query.get(session['user_id'])
        purchases = Purchase.query.filter_by(user_id=session['user_id']).order_by(Purchase.timestamp.desc()).all()
        return render_template('dashboard.html', username=session['username'], purchases=purchases, user = user, is_admin=False)
    

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/purchase', methods=['POST'])
def purchase():
    if 'user_id' not in session:
        flash("Please log in to reserve a spot.")
        return redirect(url_for('login'))

    plan_name = request.form.get('plan_name')
    if not plan_name:
        flash("Invalid plan selected.")
        return redirect(url_for('pricing'))

    session['pending_plan'] = plan_name
    return redirect(url_for('confirm_purchase'))

@app.route('/confirm_purchase', methods=['GET', 'POST'])
def confirm_purchase():
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    plan_name = session.get('pending_plan')
    if not plan_name:
        flash("No plan to confirm.")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'confirm':
            new_purchase = Purchase(user_id=session['user_id'], plan_name=plan_name)
            db.session.add(new_purchase)
            credits = PLAN_CREDITS.get(plan_name, 0)
            print(f"Adding {credits} credits for plan: {plan_name}")
            user = User.query.get(session['user_id'])
            if user:
                user.remaining_classes = (user.remaining_classes or 0) + credits
            db.session.commit()
            flash(f"Purchase confirmed for plan: {plan_name}")
        else:
            flash("Purchase canceled.")

        session.pop('pending_plan', None)
        return redirect(url_for('dashboard'))

    return render_template('confirm_purchase.html', plan_name=plan_name)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'username' not in session or session['username'] != "debo_da_zouker":
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)

    # Optionally delete purchases first if cascade is not set
    for purchase in user.purchases:
        db.session.delete(purchase)
    db.session.delete(user)
    db.session.commit()
    flash("User and their purchases deleted.")
    return redirect(url_for('dashboard'))


@app.route('/admin/purchases/delete/<int:purchase_id>', methods=['POST'])
def delete_purchase(purchase_id):
    # ✅ Admin-only access
    if 'username' not in session or session['username'] != "debo_da_zouker":
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    purchase = Purchase.query.get_or_404(purchase_id)

    db.session.delete(purchase)
    db.session.commit()
    flash("Purchase deleted successfully.")
    return redirect(url_for('dashboard'))

@app.route('/admin/users/add_class/<int:user_id>', methods=['POST'])
def add_class_credit(user_id):
    if 'username' not in session or session['username'] != "debo_da_zouker":
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)
    user.remaining_classes += 1
    db.session.commit()
    flash(f"Added 1 class credit to {user.name}. Total now: {user.remaining_classes}")
    return redirect(url_for('dashboard'))

@app.route('/admin/users/remove_class/<int:user_id>', methods=['POST'])
def remove_class_credit(user_id):
    if 'username' not in session or session['username'] != "debo_da_zouker":
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)
    if user.remaining_classes > 0:
        user.remaining_classes -= 1
        db.session.commit()
        flash(f"Removed 1 class credit from {user.name}. Remaining: {user.remaining_classes}")
    else:
        flash(f"{user.name} has no remaining classes to remove.")
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
