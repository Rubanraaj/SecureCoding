import bcrypt
import json
import os

# File to store admin credentials
ADMIN_CREDENTIALS_FILE = "admin_credentials.json"
# File to store patient data
PATIENT_DATA_FILE = "patient_data.json"

# Load admin credentials from file
def load_admin_credentials():
    if os.path.exists(ADMIN_CREDENTIALS_FILE):
        with open(ADMIN_CREDENTIALS_FILE, "r") as file:
            return json.load(file)
    return {}

# Save admin credentials to file
def save_admin_credentials(credentials):
    with open(ADMIN_CREDENTIALS_FILE, "w") as file:
        json.dump(credentials, file)

# Load patient data from file
def load_patient_data():
    if os.path.exists(PATIENT_DATA_FILE):
        with open(PATIENT_DATA_FILE, "r") as file:
            return json.load(file)
    return []

# Save patient data to file
def save_patient_data(patients):
    with open(PATIENT_DATA_FILE, "w") as file:
        json.dump(patients, file)

# Hash a passcode using bcrypt
def hash_passcode(passcode):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(passcode.encode(), salt)

# Verify a passcode against its hash
def verify_passcode(passcode, hashed_passcode):
    return bcrypt.checkpw(passcode.encode(), hashed_passcode)


# Admin registration
def register_admin():
    username = input("Enter a username: ")
    passcode = input("Enter a passcode: ")

    credentials = load_admin_credentials()
    if username in credentials:
        print("Username already exists. Please choose another.")
        return

    hashed_passcode = hash_passcode(passcode)
    credentials[username] = hashed_passcode.decode()  # Store as string
    save_admin_credentials(credentials)
    print("Admin registered successfully!")

# Admin login
def login_admin():
    username = input("Enter your username: ")
    passcode = input("Enter your passcode: ")

    credentials = load_admin_credentials()
    if username not in credentials:
        print("Username not found.")
        return False

    hashed_passcode = credentials[username].encode()  # Convert back to bytes
    if verify_passcode(passcode, hashed_passcode):
        print("Login successful!")
        return True
    else:
        print("Invalid passcode.")
        return False

# Patient management functions
def add_patient():
    name = input("Enter patient name: ")
    age = input("Enter patient age: ")
    condition = input("Enter patient condition: ")

    patients = load_patient_data()
    patients.append({"name": name, "age": age, "condition": condition})
    save_patient_data(patients)
    print("Patient added successfully!")

def view_patients():
    patients = load_patient_data()
    if not patients:
        print("No patients found.")
    else:
        for patient in patients:
            print(f"Name: {patient['name']}, Age: {patient['age']}, Condition: {patient['condition']}")

# Main application
def main():
    failed_attempts = 0
    MAX_ATTEMPTS = 3

    while True:
        print("\nWelcome to the Hospital Management System")
        print("1. Register Admin")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            register_admin()
        elif choice == "2":
            if failed_attempts >= MAX_ATTEMPTS:
                print("Too many failed attempts. You are locked out.")
                break

            if login_admin():
                while True:
                    print("\nPatient Management")
                    print("1. Add Patient")
                    print("2. View Patients")
                    print("3. Logout")
                    action = input("Choose an option: ")

                    if action == "1":
                        add_patient()
                    elif action == "2":
                        view_patients()
                    elif action == "3":
                        print("Logged out.")
                        break
                    else:
                        print("Invalid choice. Please try again.")
            else:
                failed_attempts += 1
                print(f"Failed attempts: {failed_attempts}")
        elif choice == "3":
            print("Exiting the system. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()