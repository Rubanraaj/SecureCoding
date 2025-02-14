import rsa
import json
import os

# File to store patient data
PATIENT_DATA_FILE = "patient_data.json"

# Generate RSA key pair and save to files
def generate_rsa_key_pair():
    (public_key, private_key) = rsa.newkeys(2048)

    # Save the private key to a file
    with open('private_key.pem', 'wb') as private_key_file:
        private_key_bytes = private_key.save_pkcs1(format='PEM')
        private_key_file.write(private_key_bytes)

    # Save the public key to a file
    with open('public_key.pem', 'wb') as public_key_file:
        public_key_bytes = public_key.save_pkcs1(format='PEM')
        public_key_file.write(public_key_bytes)

    print("RSA key pair generated and saved to 'private_key.pem' and 'public_key.pem'.")

# Load the private key from a file
def load_private_key():
    with open('private_key.pem', 'rb') as private_key_file:
        private_key_data = private_key_file.read()
        private_key = rsa.PrivateKey.load_pkcs1(private_key_data)
    return private_key

# Load the public key from a file
def load_public_key():
    with open('public_key.pem', 'rb') as public_key_file:
        public_key_data = public_key_file.read()
        public_key = rsa.PublicKey.load_pkcs1(public_key_data)
    return public_key

# Encrypt data using the doctor's public key
def encrypt_data(data, public_key):
    encrypted_data = rsa.encrypt(data.encode('utf-8'), public_key)
    return encrypted_data.hex()  # Convert to hex string for storage

# Decrypt data using the doctor's private key
def decrypt_data(encrypted_data_hex, private_key):
    encrypted_data = bytes.fromhex(encrypted_data_hex)  # Convert hex string back to bytes
    decrypted_data = rsa.decrypt(encrypted_data, private_key)
    return decrypted_data.decode('utf-8')

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

# Add patient (encrypt sensitive data)
def add_patient(public_key):
    name = input("Enter patient name: ")
    age = input("Enter patient age: ")
    email = input("Enter patient email: ")
    ssn = input("Enter patient SSN: ")
    illness_history = input("Enter patient illness history: ")

    if not name or not age or not email or not ssn or not illness_history:
        print("All fields are required!")
        return

    # Encrypt sensitive data
    encrypted_email = encrypt_data(email, public_key)
    encrypted_ssn = encrypt_data(ssn, public_key)
    encrypted_illness = encrypt_data(illness_history, public_key)

    patients = load_patient_data()
    patients.append({
        "name": name,
        "age": age,
        "email": encrypted_email,
        "ssn": encrypted_ssn,
        "illness_history": encrypted_illness,
    })
    save_patient_data(patients)
    print("Patient added successfully!")

# View patients (decrypt sensitive data)
def view_patients(private_key):
    patients = load_patient_data()
    if not patients:
        print("No patients found.")
    else:
        print("\nPatient Records:")
        for patient in patients:
            decrypted_patient = {
                "name": patient["name"],
                "age": patient["age"],
                "email": decrypt_data(patient["email"], private_key),
                "ssn": decrypt_data(patient["ssn"], private_key),
                "illness_history": decrypt_data(patient["illness_history"], private_key),
            }
            print(f"Name: {decrypted_patient['name']}")
            print(f"Age: {decrypted_patient['age']}")
            print(f"Email: {decrypted_patient['email']}")
            print(f"SSN: {decrypted_patient['ssn']}")
            print(f"Illness History: {decrypted_patient['illness_history']}")
            print("-" * 30)

# Main application
def main():
    if not os.path.exists('private_key.pem') or not os.path.exists('public_key.pem'):
        print("Generating RSA key pair...")
        generate_rsa_key_pair()

    # Load keys
    private_key = load_private_key()
    public_key = load_public_key()

    while True:
        print("\nWelcome to the Hospital Management System")
        print("1. Add Patient (Encrypt Data)")
        print("2. View Patients (Decrypt Data)")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            add_patient(public_key)
        elif choice == "2":
            view_patients(private_key)
        elif choice == "3":
            print("Exiting the system. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()