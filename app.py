import re
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from abc import ABC, abstractmethod

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:user%password@localhost:3306/libraryz'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

def is_valid_email(email):
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email)

def is_valid_username(username):
    return re.match(r"^[a-zA-Z0-9_]{3,20}$", username)

def is_strong_password(password):
    return re.match(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$", password)

#Custom Exception
class BookUnavailableError(Exception):
    def __init__(self, message="Book is currently unavailable."):
        self.message = message
        super().__init__(self.message)

#Custom Exception
class UserAlreadyExistsException(Exception):
    def __init__(self, message="User or Email already exists."):
        self.message = message
        super().__init__(self.message)

#Abstraction for user service
class AbstractUserService(ABC):
    @abstractmethod
    def register_user(self, email, username, password, role):
        pass

    @abstractmethod
    def authenticate_user(self, email, password):
        pass

class UserService(AbstractUserService):
    __instance = None

    def __init__(self):
        if UserService.__instance:
            raise Exception("This is a singleton class. Use get_instance().")
        UserService.__instance = self

    @staticmethod
    def get_instance():
        if UserService.__instance is None:
            UserService()
        return UserService.__instance

    def register_user(self, email, username, password, role):
        if User.query.filter_by(email=email).first():
            raise UserAlreadyExistsException()
        if User.query.filter_by(username=username).first():
            raise UserAlreadyExistsException()
        hashed_password = generate_password_hash(password)
        new_user = User(email=email, username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

    def authenticate_user(self, email, password):
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            return user
        return None

# Abstraction for book service
class AbstractBookService(ABC):
    @abstractmethod
    def add_book(self, title, author, total_quantity, category):
        pass

    @abstractmethod
    def update_book(self, book_id, title, author, total_quantity, category):
        pass

    @abstractmethod
    def delete_book(self, book_id):
        pass

# BookService implementing singleton, abstraction, classmethod
class BookService(AbstractBookService):
    __instance = None

    def __init__(self):
        if BookService.__instance:
            raise Exception("Use get_instance().")
        BookService.__instance = self

    @classmethod
    def get_instance(cls):
        if cls.__instance is None:
            cls()
        return cls.__instance

    def add_book(self, title, author, total_quantity, category):
        if Book.query.filter_by(title=title, author=author).first():
            raise ValueError("Book already exists.")
        new_book = Book(title=title, author=author, total_quantity=total_quantity, category=category)
        db.session.add(new_book)
        db.session.commit()

    def update_book(self, book_id, title, author, total_quantity, category):
        book = Book.query.get_or_404(book_id)
        remainder = book.total_quantity - book.quantity
        book.title = title
        book.author = author
        book.total_quantity = total_quantity
        book.quantity = total_quantity - remainder
        book.category = category
        book.status = 'Available' if book.quantity > 0 else 'Unavailable'
        db.session.commit()

    def delete_book(self, book_id):
        book = Book.query.get(book_id)
        if not book:
            raise ValueError("Book not found.")
        db.session.delete(book)
        db.session.commit()

    def search_books(self, query):
        if query == 'all':
            return Book.query.all()

        return Book.query.filter(
            (Book.title.ilike(f"%{query}%")) |
            (Book.author.ilike(f"%{query}%")) |
            (Book.category.ilike(f"%{query}%"))
        ).all()

class LogService:
    @staticmethod
    def get_logs(user_id, role, search_term=''):
        query = Log.query

        if role == 'Admin':
            if search_term:
                query = query.join(Book).join(User).filter(
                    (Book.title.ilike(f"%{search_term}%")) |
                    (User.username.ilike(f"%{search_term}%")) |
                    (Log.action.ilike(f"%{search_term}%"))
                )
        else:
            query = query.filter_by(user_id=user_id)
            if search_term:
                query = query.join(Book).filter(
                    (Book.title.ilike(f"%{search_term}%")) |
                    (Log.action.ilike(f"%{search_term}%"))
                )
        return query.order_by(Log.timestamp.desc()).all()

#Inheritance and encapsulation
class Item:
    def __init__(self, title):
        self._title = title

    def get_title(self):
        return self._title

#Book inherits from Item (Single Inheritance)
class Book(db.Model, Item):
    __tablename__ = 'book'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    total_quantity = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, default=0)
    category = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default='Available')

    def __init__(self, title, author, total_quantity, category):
        Item.__init__(self, title)
        self.title = title
        self.author = author
        self.total_quantity = total_quantity
        self.quantity = total_quantity
        self.category = category
        self.status = 'Available'

    #Polymorphism (method overriding)
    def get_title(self):
        return f"Book: {self.title}"

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False)

class Log(db.Model):
    __tablename__ = 'log'
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id', ondelete="SET NULL"), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(10))  # "borrow" or "return"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    book = db.relationship('Book', backref=db.backref('logs', passive_deletes=True))
    user = db.relationship('User', backref=db.backref('logs', passive_deletes=True))

user_service = UserService.get_instance()
book_service = BookService.get_instance()

#ROUTES

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # Regex validations
        if not is_valid_username(username):
            flash('Username must be 3-20 characters: letters, numbers, underscores only.', 'danger')
            return redirect('/register')

        if not is_valid_email(email):
            flash('Invalid email format.', 'danger')
            return redirect('/register')

        if not is_strong_password(password):
            flash('Password must be at least 8 characters and contain letters and numbers.', 'danger')
            return redirect('/register')
        
        try:
            user_service.register_user(email, username, password, role)
            flash('Registration successful! Please login.', 'success')
            return redirect('/login')
        except UserAlreadyExistsException:
            flash('Username or email already exists!', 'danger')
            return redirect('/register')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not is_valid_email(email):
            flash('Invalid username format.', 'danger')
            return redirect('/login')

        user = user_service.authenticate_user(email, password)
        if user:
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'danger')
            return redirect('/login')
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

    latest_logs = {}
    for book in books:
        user_logs = [log for log in book.logs if log.user_id == session['user_id']]
        latest_log = sorted(user_logs, key=lambda l: l.timestamp, reverse=True)[0] if user_logs else None
        latest_logs[book.id] = latest_log

    return render_template(
        'dashboard.html',
        books=books,
        role=session['role'],
        username=session['username'],
        borrowed_books=borrowed_books,
        latest_logs=latest_logs
    )

@app.route('/delete_book/<int:book_id>', methods=['POST'])
def delete_book(book_id):
    if session.get('role') != 'Admin':
        flash("Only Admins can delete books.")
        return redirect(url_for('dashboard'))

    book_service.delete_book(book_id)
    flash('Book deleted successfully.')
    return redirect(url_for('dashboard'))

@app.route('/borrow/<int:book_id>', methods=['POST'])
def borrow_book(book_id):
    if session.get('role') != 'Student':
        flash('Only students can borrow or return books.')
        return redirect(url_for('dashboard'))
    try:
        book = Book.query.get_or_404(book_id)
        user_id = session.get('user_id')
        latest_log = Log.query.filter_by(user_id=user_id, book_id=book.id).order_by(Log.timestamp.desc()).first()
        if latest_log and latest_log.action == 'borrow':
            book.quantity += 1
            if book.quantity > 0:
                book.status = 'Available'
            db.session.add(Log(user_id=user_id, book_id=book.id, action='return'))
        elif book.quantity > 0:
            book.quantity -= 1
            book.status = 'Borrowed'
            db.session.add(Log(user_id=user_id, book_id=book.id, action='borrow'))
        else:
            raise BookUnavailableError()
        db.session.commit()
        flash(f'Action completed for "{book.title}".')
    except BookUnavailableError as e:
        flash(str(e))
    return redirect(url_for('dashboard'))

@app.route('/add_book', methods=['GET', 'POST'])
def add_book():
    if session.get('role') != 'Admin':
        flash("Only Admins can add books.")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        try:
            book_service.add_book(
                request.form['title'],
                request.form['author'],
                int(request.form['quantity']),
                request.form['category']
            )
            flash('Book added successfully.')
            return redirect(url_for('dashboard'))
        except ValueError as ve:
            flash(str(ve))
    return render_template('add_book.html')

@app.route('/update_book/<int:book_id>', methods=['GET', 'POST'])
def update_book(book_id):
    if session.get('role') != 'Admin':
        flash("Only Admins can update books.")
        return redirect(url_for('dashboard'))
    book = Book.query.get_or_404(book_id)
    if request.method == 'POST':
        book_service.update_book(
            book_id,
            request.form['title'],
            request.form['author'],
            int(request.form['total_quantity']),
            request.form['category']
        )
        flash('Book updated successfully.')
        return redirect(url_for('dashboard'))
    return render_template('update_book.html', book=book)

log_service = LogService()

@app.route('/logbook', methods=['GET'])
def logbook():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    search = request.args.get('search', '').strip()
    logs = log_service.get_logs(session['user_id'], session['role'], search)
    return render_template('logbook.html', logs=logs, search=search)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    if not query:
        flash('Please enter a search query.', 'warning')
        return redirect(url_for('dashboard'))

    books = book_service.search_books(query)
    
    latest_logs = {}
    if 'user_id' in session:
        for book in books:
            latest_log = Log.query.filter_by(book_id=book.id).order_by(Log.timestamp.desc()).first()
            latest_logs[book.id] = latest_log

    return render_template('dashboard.html', books=books, role=session.get('role'), username=session.get('username'), borrowed_books=[], latest_logs=latest_logs)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
