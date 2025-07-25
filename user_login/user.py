import sqlite3
import hashlib
import getpass

# Database Setup 
def set_database():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            is_logged_in INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    return conn, cursor


#  Hashing Function 
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# user registration

def register(cursor, conn):
    username = input("Enter a new username: ").strip()
    password = getpass.getpass("Enter a new password: ").strip()

    
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        print("Username already exists.")
        return

   # Hash the password and store user info in the database
    hashed_pw = hash_password(password)
    cursor.execute("INSERT INTO users (username, password, is_logged_in) VALUES (?, ?, 0)", 
                   (username, hashed_pw))
    conn.commit()

    print("Registration successful.")

    
# user login
def login(cursor, conn, current_user):
    if current_user[0]:
        print(f" Already logged in as {current_user[0]}. Please logout first.")
        return

    username = input("Enter your username: ").strip()
    password = getpass.getpass("Enter your password: ").strip()
    hashed_pw = hash_password(password)

    cursor.execute("SELECT password, is_logged_in FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if not result:
        print("User not found.")
        return

    stored_pw, is_logged_in = result
    if is_logged_in:
        print("User is already logged in.")
        return
    if stored_pw != hashed_pw:
        print("Incorrect password.")
        return

    cursor.execute("UPDATE users SET is_logged_in = 1 WHERE username = ?", (username,))
    conn.commit()
    current_user[0] = username
    print(f"Logged in as {username}.") 


#  Logout
def logout(cursor, conn, current_user):
    if not current_user[0]:
        print("No user is currently logged in.")
        return

    cursor.execute("UPDATE users SET is_logged_in = 0 WHERE username = ?", (current_user[0],))
    conn.commit()
    print(f"{current_user[0]} logged out.")
    current_user[0] = None

#  Change Password 
def change_password(cursor, conn, current_user):
    if not current_user[0]:
        print("Please log in to change your password.")
        return

    old_pw = getpass.getpass("Enter your current password: ").strip()
    new_pw = getpass.getpass("Enter your new password: ").strip()

    cursor.execute("SELECT password FROM users WHERE username = ?", (current_user[0],))
    stored_pw = cursor.fetchone()[0]

    if hash_password(old_pw) != stored_pw:
        print("Incorrect current password.")
        return

    new_hashed = hash_password(new_pw)
    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_hashed, current_user[0]))
    conn.commit()
    print(" Password changed successfully.")

# users
def display_users(cursor):
    print("\n=== Users Table ===")
    cursor.execute("SELECT username, password, is_logged_in FROM users")
    rows = cursor.fetchall()

    if not rows:
        print("No users found.")
        return

    print(f"{'Username':<20} {'Password (hashed)':<64} {'Logged In'}")
    print("-" * 95)
    for row in rows:
        username, password, is_logged_in = row
        print(f"{username:<20} {password:<64} {is_logged_in}")



# main function
def main():
    conn, cursor = set_database()
    current_user = [None]  

    while True:
        print("\n=== User Management Menu ===")
        print("1. Register")
        print("2. Login")
        print("3. Logout")
        print("4. Change Password")
        print("5. Exit")
        print("6. See table" )
        choice = input("Select an option from (1-6): ").strip()

        if choice == '1':
            register(cursor, conn)
        elif choice == '2':
            login(cursor, conn, current_user)
        elif choice == '3':
            logout(cursor, conn, current_user)
        elif choice == '4':
            change_password(cursor, conn, current_user)
        elif choice == '5':
            if current_user[0]:
                logout(cursor, conn, current_user)
            print("Exiting ... Thank you")
            break
        elif choice == '6':
            display_users(cursor)
        else:
            print("Invalid option. Please try again.")

    conn.close()

#  Entry Point -- Run only if directly run -----------------
if __name__ == "__main__":
    main()
