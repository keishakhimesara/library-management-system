from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:keisha%402005@localhost:3306/library'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

# User model with role
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # "Admin" or "Student"

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default='Available')

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    #user = db.Column(db.String(100), db.ForeignKey('user.username'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    action = db.Column(db.String(10), nullable=False)  # "borrow" or "return"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='logs')
    book = db.relationship('Book', backref='logs')

# Routes
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
    return render_template('dashboard.html', books=books, role=session['role'])

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
            category = request.form['category']
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
    if request.method == 'POST':
        book.title = request.form['title']
        book.author = request.form['author']
        book.quantity = int(request.form['quantity'])
        book.category = request.form['category']
        db.session.commit()
        flash('Book updated successfully.')
        return redirect(url_for('dashboard'))
    return render_template('update_book.html', book=book)

@app.route('/delete/<int:book_id>', methods=['POST'])
def delete_book(book_id):
    try:
        if session.get('role') != 'Admin':
            flash('Unauthorized')
            return redirect(url_for('dashboard'))
        book = Book.query.get_or_404(book_id)
        db.session.delete(book)
        db.session.commit()
        return redirect(url_for('dashboard'))
    except Exception as e:
        return ({'error': str(e)}), 400

# @app.route('/delete_book/<int:book_id>')
# def delete_book(book_id):
#     if session.get('role') != 'Admin':
#         flash('Unauthorized')
#         return redirect(url_for('dashboard'))
#     book = Book.query.get_or_404(book_id)
#     db.session.delete(book)
#     db.session.commit()
#     flash('Book deleted.')
#     return redirect(url_for('dashboard'))

@app.route('/borrow/<int:book_id>', methods=['POST'])
def borrow_book(book_id):
    book = Book.query.get_or_404(book_id)
    user_id = session.get('user_id')
    user_name = session.get('username')

    if not user_id or not user_name:
        flash('User session not found. Please log in again.', 'danger')
        return redirect(url_for('login'))

    if book.quantity > 0:
        book.quantity -= 1

        if book.status == 'Available':
            book.status = 'Borrowed'
            db.session.commit()

            log_entry = Log(
                user_id=user_id,
                book_id=book.id,
                action='borrow',
                timestamp=datetime.now()
            )
            db.session.add(log_entry)
            db.session.commit()

            flash(f'You borrowed "{book.title}".', 'success')

        elif book.status == 'Borrowed':
            book.status = 'Available'
            db.session.commit()

            log_entry = Log(
                user_id=user_id,
                book_id=book.id,
                action='return',
                timestamp=datetime.now()
            )
            db.session.add(log_entry)
            db.session.commit()

            flash(f'You returned "{book.title}".', 'info')

        else:
            flash('Invalid book status.', 'warning')
    else:
        flash('Book not available to borrow.', 'danger')

    return redirect(url_for('dashboard'))  # ✅ always return


# @app.route('/borrow/<int:book_id>', methods=['POST'], endpoint='borrow_return')
# def borrow_book(book_id):
#     if session.get('role') != 'Student':
#         flash('Only students can borrow books.')
#         return redirect(url_for('dashboard'))
#     book = Book.query.get_or_404(book_id)
#     if book.quantity > 0:
#         book.quantity -= 1
#         log = Log(user_id=session['user_id'], book_id=book.id, action='borrow')
#         db.session.add(log)
#         db.session.commit()
#         flash('Book borrowed.')
#     else:
#         flash('Book not available.')
#     return redirect(url_for('dashboard'))


@app.route('/return/<int:book_id>')
def return_book(book_id):
    if session.get('role') != 'Student':
        flash('Only students can return books.')
        return redirect(url_for('dashboard'))

    book = Book.query.get_or_404(book_id)
    book.quantity += 1

    # Reset status to "Available" if needed
    if book.status == 'Borrowed':
        book.status = 'Available'

    log = Log(
        user_id=session['user_id'],
        book_id=book.id,
        action='return',
        timestamp=datetime.utcnow()
    )

    db.session.add(log)
    db.session.commit()

    flash(f'You returned "{book.title}".')
    return redirect(url_for('dashboard'))


# @app.route('/return/<int:book_id>')
# def return_book(book_id):
#     if session.get('role') != 'Student':
#         flash('Only students can return books.')
#         return redirect(url_for('dashboard'))
#     book = Book.query.get_or_404(book_id)
#     book.quantity += 1
#     log = Log(user_id=session['user_id'], book_id=book.id, action='return')
#     db.session.add(log)
#     db.session.commit()
#     flash('Book returned.')
#     return redirect(url_for('dashboard'))

@app.route('/logbook')
def logbook():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session['role'] == 'Admin':
        logs = Log.query.all()
    else:
        logs = Log.query.filter_by(user_id=session['user_id']).all()
    return render_template('logbook.html', logs=logs)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    if not query:
        flash('Please enter a search query.', 'warning')
        return redirect(url_for('dashboard'))

    books = Book.query.filter(
        (Book.title.ilike(f"%{query}%")) |
        (Book.author.ilike(f"%{query}%")) |
        (Book.category.ilike(f"%{query}%"))
    ).all()
    return render_template('dashboard.html', books=books)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
