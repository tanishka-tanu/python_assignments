import sqlite3
import hashlib
import getpass

# --- Database Layer ---
class Database:
    def __init__(self, db_name="users.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self._setup()

    def _setup(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                is_logged_in INTEGER DEFAULT 0
            )
        """)
        self.conn.commit()

    def execute(self, query, params=()):
        self.cursor.execute(query, params)
        self.conn.commit()

    def fetchone(self, query, params=()):
        self.cursor.execute(query, params)
        return self.cursor.fetchone()

    def fetchall(self, query, params=()):
        self.cursor.execute(query, params)
        return self.cursor.fetchall()

    def close(self):
        self.conn.close()


# --- User Entity ---
class User:
    def __init__(self, username, password=None):
        self.username = username
        self.password = password  # plain-text password input

    def hashed_password(self):
        return hashlib.sha256(self.password.encode()).hexdigest()


# --- User Management Service ---
class UserManager:
    def __init__(self, db: Database):
        self.db = db
        self.current_user = None

    def register(self):
        username = input("Enter a new username: ").strip()
        password = getpass.getpass("Enter a new password: ").strip()
        if self.db.fetchone("SELECT * FROM users WHERE username = ?", (username,)):
            print("Username already exists.")
            return

        user = User(username, password)
        self.db.execute("INSERT INTO users (username, password, is_logged_in) VALUES (?, ?, 0)",
                        (user.username, user.hashed_password()))
        print("Registration successful.")

    def login(self):
        if self.current_user:
            print(f"Already logged in as {self.current_user}. Please logout first.")
            return

        username = input("Enter your username: ").strip()
        password = getpass.getpass("Enter your password: ").strip()
        user = User(username, password)

        result = self.db.fetchone("SELECT password, is_logged_in FROM users WHERE username = ?", (username,))
        if not result:
            print("User not found.")
            return

        stored_pw, is_logged_in = result
        if is_logged_in:
            print("User is already logged in.")
            return
        if user.hashed_password() != stored_pw:
            print("Incorrect password.")
            return

        self.db.execute("UPDATE users SET is_logged_in = 1 WHERE username = ?", (username,))
        self.current_user = username
        print(f"Logged in as {username}.")

    def logout(self):
        if not self.current_user:
            print("No user is currently logged in.")
            return

        self.db.execute("UPDATE users SET is_logged_in = 0 WHERE username = ?", (self.current_user,))
        print(f"{self.current_user} logged out.")
        self.current_user = None

    def change_password(self):
        if not self.current_user:
            print("Please log in to change your password.")
            return

        old_pw = getpass.getpass("Enter your current password: ").strip()
        new_pw = getpass.getpass("Enter your new password: ").strip()

        result = self.db.fetchone("SELECT password FROM users WHERE username = ?", (self.current_user,))
        if not result:
            print("User not found.")
            return

        stored_pw = result[0]
        if hashlib.sha256(old_pw.encode()).hexdigest() != stored_pw:
            print("Incorrect current password.")
            return

        new_hashed = hashlib.sha256(new_pw.encode()).hexdigest()
        self.db.execute("UPDATE users SET password = ? WHERE username = ?", (new_hashed, self.current_user))
        print("Password changed successfully.")

    def display_users(self):
        print("\n=== Users Table ===")
        users = self.db.fetchall("SELECT username, password, is_logged_in FROM users")

        if not users:
            print("No users found.")
            return

        print(f"{'Username':<20} {'Password (hashed)':<64} {'Logged In'}")
        print("-" * 95)
        for username, password, is_logged_in in users:
            print(f"{username:<20} {password:<64} {is_logged_in}")


# --- Main Application ---
class App:
    def __init__(self):
        self.db = Database()
        self.user_manager = UserManager(self.db)

    def run(self):
        while True:
            print("\n=== User Management Menu ===")
            print("1. Register")
            print("2. Login")
            print("3. Logout")
            print("4. Change Password")
            print("5. Exit")
            print("6. See table")

            choice = input("Select an option from (1-6): ").strip()

            if choice == '1':
                self.user_manager.register()
            elif choice == '2':
                self.user_manager.login()
            elif choice == '3':
                self.user_manager.logout()
            elif choice == '4':
                self.user_manager.change_password()
            elif choice == '5':
                if self.user_manager.current_user:
                    self.user_manager.logout()
                print("Exiting... Thank you.")
                self.db.close()
                break
            elif choice == '6':
                self.user_manager.display_users()
            else:
                print("Invalid option. Please try again.")


# --- Entry Point ---
if __name__ == "__main__":
    App().run()
