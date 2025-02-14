import rsa
import json
import os

# File to store medical reports
MEDICAL_REPORTS_FILE = "medical_reports.json"

# Generate RSA key pair and save to files
def generate_rsa_key_pair():
    (public_key, private_key) = rsa.newkeys(2048)

    # Save the private key to a file
    with open('doctor_private_key.pem', 'wb') as private_key_file:
        private_key_bytes = private_key.save_pkcs1(format='PEM')
        private_key_file.write(private_key_bytes)

    # Save the public key to a file
    with open('doctor_public_key.pem', 'wb') as public_key_file:
        public_key_bytes = public_key.save_pkcs1(format='PEM')
        public_key_file.write(public_key_bytes)

    print("RSA key pair generated and saved to 'doctor_private_key.pem' and 'doctor_public_key.pem'.")

# Load the private key from a file
def load_private_key():
    with open('doctor_private_key.pem', 'rb') as private_key_file:
        private_key_data = private_key_file.read()
        private_key = rsa.PrivateKey.load_pkcs1(private_key_data)
    return private_key

# Load the public key from a file
def load_public_key():
    with open('doctor_public_key.pem', 'rb') as public_key_file:
        public_key_data = public_key_file.read()
        public_key = rsa.PublicKey.load_pkcs1(public_key_data)
    return public_key

# Load medical reports from file
def load_medical_reports():
    if os.path.exists(MEDICAL_REPORTS_FILE):
        with open(MEDICAL_REPORTS_FILE, "r") as file:
            return json.load(file)
    return []

# Save medical reports to file
def save_medical_reports(reports):
    with open(MEDICAL_REPORTS_FILE, "w") as file:
        json.dump(reports, file)

# Create and sign a medical report
def create_medical_report(private_key):
    patient_name = input("Enter patient name: ")
    diagnosis = input("Enter diagnosis: ")
    treatment = input("Enter treatment: ")

    if not patient_name or not diagnosis or not treatment:
        print("All fields are required!")
        return

    # Create the medical report
    report = {
        "patient_name": patient_name,
        "diagnosis": diagnosis,
        "treatment": treatment,
    }

    # Convert the report to a string for hashing
    report_string = json.dumps(report, sort_keys=True)

    # Sign the report
    signature = rsa.sign(report_string.encode('utf-8'), private_key, 'SHA-256')
    signature_hex = signature.hex()  # Convert to hex string for storage

    # Save the report and signature
    reports = load_medical_reports()
    reports.append({
        "report": report,
        "signature": signature_hex,
    })
    save_medical_reports(reports)
    print("Medical report created and signed successfully!")

# Verify a medical report
def verify_medical_report(public_key):
    reports = load_medical_reports()
    if not reports:
        print("No medical reports found.")
        return

    print("\nMedical Reports:")
    for i, report_data in enumerate(reports):
        print(f"\nReport {i + 1}:")
        print(f"Patient Name: {report_data['report']['patient_name']}")
        print(f"Diagnosis: {report_data['report']['diagnosis']}")
        print(f"Treatment: {report_data['report']['treatment']}")

        # Verify the signature
        report_string = json.dumps(report_data['report'], sort_keys=True)
        signature = bytes.fromhex(report_data['signature'])
        try:
            rsa.verify(report_string.encode('utf-8'), signature, public_key)
            print("Signature is valid. The report is authentic.")
        except rsa.VerificationError:
            print("Signature is invalid. The report may have been tampered with.")
        print("-" * 30)

# Main application
def main():
    if not os.path.exists('doctor_private_key.pem') or not os.path.exists('doctor_public_key.pem'):
        print("Generating RSA key pair...")
        generate_rsa_key_pair()

    # Load keys
    private_key = load_private_key()
    public_key = load_public_key()

    while True:
        print("\nWelcome to the Hospital Management System")
        print("1. Create and Sign Medical Report")
        print("2. Verify Medical Reports")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            create_medical_report(private_key)
        elif choice == "2":
            verify_medical_report(public_key)
        elif choice == "3":
            print("Exiting the system. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()