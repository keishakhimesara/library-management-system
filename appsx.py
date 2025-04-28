from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:username%password@localhost:3306/library'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    total_quantity = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, default=total_quantity)
    category = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default='Available')

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    action = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='logs')
    book = db.relationship('Book', backref='logs')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']

        if User.query.filter_by(email=email).first():
            flash('Email already registered.')
            return redirect(url_for('register'))

        new_user = User(email=email, username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.')
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
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    books = Book.query.all()
    borrowed_books = []

    if session['role'] == 'Student':
        logs = Log.query.filter_by(user_id=session['user_id']).order_by(Log.timestamp.desc()).all()
        borrowed_status = {}
        for log in logs:
            if log.book_id not in borrowed_status:
                borrowed_status[log.book_id] = log.action
        borrowed_books = [book_id for book_id, action in borrowed_status.items() if action == 'borrow']

    # 📌 Add most recent log per book
    latest_logs = {}
    for book in books:
        sorted_logs = sorted(book.logs, key=lambda l: l.timestamp, reverse=True)
        latest_logs[book.id] = sorted_logs[0] if sorted_logs else None

    return render_template('dashboard.html', books=books, role=session['role'], borrowed_books=borrowed_books, latest_logs=latest_logs)

@app.route('/add_book', methods=['GET', 'POST'])
def add_book():
    if session.get('role') != 'Admin':
        flash('Unauthorized')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        new_book = Book(
            title=request.form['title'],
            author=request.form['author'],
            quantity=int(request.form['quantity']),
            total_quantity=int(request.form['quantity']),
            category=request.form['category']
        )
        db.session.add(new_book)
        db.session.commit()
        flash('Book added successfully.')
        return redirect(url_for('dashboard'))
    return render_template('add_book.html')

@app.route('/update_book/<int:book_id>', methods=['GET', 'POST'])
def update_book(book_id):
    if session.get('role') != 'Admin':
        flash('Unauthorized')
        return redirect(url_for('dashboard'))
    book = Book.query.get_or_404(book_id)
    remainder = book.total_quantity - book.quantity 
    if request.method == 'POST':
        book.title = request.form['title']
        book.author = request.form['author']
        book.total_quantity = int(request.form['quantity'])
        book.quantity = book.total_quantity - remainder
        book.category = request.form['category']
        db.session.commit()
        flash('Book updated successfully.')
        return redirect(url_for('dashboard'))
    return render_template('update_book.html', book=book)

@app.route('/delete/<int:book_id>', methods=['POST'])
def delete_book(book_id):
    if session.get('role') != 'Admin':
        flash('Unauthorized')
        return redirect(url_for('dashboard'))
    book = Book.query.get_or_404(book_id)
    db.session.delete(book)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/borrow/<int:book_id>', methods=['POST'])
def borrow_book(book_id):
    if session.get('role') != 'Student':
        flash('Only students can borrow or return books.')
        return redirect(url_for('dashboard'))

    book = Book.query.get_or_404(book_id)

    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in again.', 'danger')
        return redirect(url_for('login'))

    book = Book.query.get_or_404(book_id)

    latest_log = Log.query.filter_by(user_id=user_id, book_id=book.id).order_by(Log.timestamp.desc()).first()

    if latest_log and latest_log.action == 'borrow':
        # Toggle to RETURN
        book.quantity += 1
        if book.quantity > 0:
            book.status = 'Available'
        db.session.add(Log(user_id=user_id, book_id=book.id, action='return'))
        db.session.commit()
        flash(f'You returned "{book.title}".', 'info')
        return redirect(url_for('dashboard'))

    elif book.quantity > 0:
        # Toggle to BORROW
        book.quantity -= 1
        book.status = 'Borrowed'
        db.session.add(Log(user_id=user_id, book_id=book.id, action='borrow'))
        db.session.commit()
        flash(f'You borrowed "{book.title}".', 'success')
        return redirect(url_for('dashboard'))

    else:
        flash('Book not available to borrow.', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/logbook', methods=['GET'])
def logbook():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    search = request.args.get('search', '').strip()
    query = Log.query

    if session['role'] == 'Admin':
        if search:
            query = query.join(Book).join(User).filter(
                (Book.title.ilike(f"%{search}%")) |
                (User.username.ilike(f"%{search}%")) |
                (Log.action.ilike(f"%{search}%"))
            )
        logs = query.order_by(Log.timestamp.desc()).all()
    else:
        query = query.filter_by(user_id=session['user_id'])
        if search:
            query = query.join(Book).filter(
                (Book.title.ilike(f"%{search}%")) |
                (Log.action.ilike(f"%{search}%"))
            )
        logs = query.order_by(Log.timestamp.desc()).all()

    return render_template('logbook.html', logs=logs, search=search)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    if not query:
        flash('Please enter a search query.', 'warning')
        return redirect(url_for('dashboard'))
    if query == 'all':
        return redirect(url_for('dashboard'))
    books = Book.query.filter(
        (Book.title.ilike(f"%{query}%")) |
        (Book.author.ilike(f"%{query}%")) |
        (Book.category.ilike(f"%{query}%"))
    ).all()

    latest_logs = {}
    if 'user_id' in session:
        for book in books:
            latest_log = Log.query.filter_by(book_id=book.id).order_by(Log.timestamp.desc()).first()
            latest_logs[book.id] = latest_log
    return render_template('dashboard.html', books=books, role=session.get('role'), latest_logs=latest_logs)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
