Library Management System

A simple and efficient Library Management System built using **Python**, **Flask**, and **MySQL**.  
This project helps manage book records, user borrowing/return activities, and role-based access for students and admins.

---

Features
- **User Authentication:** Admin and Student login functionality
- **Role-Based Access:**
  - Admins: Add, update, delete books; view all logs
  - Students: Borrow and return books; view their own borrowing history
- **Book Management:** CRUD operations (Create, Read, Update, Delete) on books
- **Log System:** Borrowing and returning transactions recorded
- **Responsive UI:** Built with Bootstrap for better user experience
- **Exception Handling:** Handles invalid inputs and system errors gracefully

## 🛠️ Tech Stack
- **Frontend:** HTML, CSS, Bootstrap
- **Backend:** Python, Flask
- **Database:** MySQL (with SQLAlchemy ORM)
- **Tools:** Git, GitHub, VSCode, MySQL Workbench

## 🧩 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

### 2. Install Dependencies
Make sure you have Python installed. Then run:
```bash
pip install -r requirements.txt
```

### 3. Set up the Database
- Create a new MySQL database (e.g., `library_db`).
- Update your database name in app.config
- Update your n=username and root passwrods too

### 4. Run the App
```bash
python app.py
```
Visit `http://localhost:5000/` in your browser.

🔥 Author
**Keisha Khimesara**  
- 📧 keishakhimesara@icloud.com
