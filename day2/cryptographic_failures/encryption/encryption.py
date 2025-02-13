import bcrypt
import json
import os
from cryptography.fernet import Fernet

# File to store admin credentials
ADMIN_CREDENTIALS_FILE = "admin_credentials.json"
# File to store patient data
PATIENT_DATA_FILE = "patient_data.json"

# Generate a new encryption key
def generate_key():
    return Fernet.generate_key()

# Encrypt data using Fernet
def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

# Decrypt data using Fernet
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data.encode()).decode()

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
        return None

    hashed_passcode = credentials[username].encode()  # Convert back to bytes
    if verify_passcode(passcode, hashed_passcode):
        print("Login successful!")
        return generate_key()  # Generate a new encryption key for the session
    else:
        print("Invalid passcode.")
        return None

# Add patient
def add_patient(encryption_key):
    name = input("Enter patient name: ")
    age = input("Enter patient age: ")
    email = input("Enter patient email: ")
    ssn = input("Enter patient SSN: ")
    illness_history = input("Enter patient illness history: ")

    if not name or not age or not email or not ssn or not illness_history:
        print("All fields are required!")
        return

    # Encrypt sensitive data
    encrypted_email = encrypt_data(email, encryption_key)
    encrypted_ssn = encrypt_data(ssn, encryption_key)
    encrypted_illness = encrypt_data(illness_history, encryption_key)

    patients = load_patient_data()
    patients.append({
        "name": name,
        "age": age,
        "email": encrypted_email,
        "ssn": encrypted_ssn,
        "illness_history": encrypted_illness
    })
    save_patient_data(patients)
    print("Patient added successfully!")

# View patients
def view_patients(encryption_key):
    patients = load_patient_data()
    if not patients:
        print("No patients found.")
    else:
        print("\nPatient Records:")
        for patient in patients:
            decrypted_patient = {
                "name": patient["name"],
                "age": patient["age"],
                "email": decrypt_data(patient["email"], encryption_key),
                "ssn": decrypt_data(patient["ssn"], encryption_key),
                "illness_history": decrypt_data(patient["illness_history"], encryption_key)
            }
            print(f"Name: {decrypted_patient['name']}")
            print(f"Age: {decrypted_patient['age']}")
            print(f"Email: {decrypted_patient['email']}")
            print(f"SSN: {decrypted_patient['ssn']}")
            print(f"Illness History: {decrypted_patient['illness_history']}")
            print("-" * 30)

# Main application
def main():
    encryption_key = None
    while True:
        print("\nWelcome to the Hospital Management System")
        print("1. Register Admin")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            register_admin()
        elif choice == "2":
            encryption_key = login_admin()
            if encryption_key:
                while True:
                    print("\nPatient Management")
                    print("1. Add Patient")
                    print("2. View Patients")
                    print("3. Logout")
                    action = input("Choose an option: ")

                    if action == "1":
                        add_patient(encryption_key)
                    elif action == "2":
                        view_patients(encryption_key)
                    elif action == "3":
                        print("Logged out.")
                        encryption_key = None
                        break
                    else:
                        print("Invalid choice. Please try again.")
        elif choice == "3":
            print("Exiting the system. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()