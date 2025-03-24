import time
import uuid

enrolled_fingerprints = {}

def enroll_fingerprint(username):
    print(f"\n--- Enrolling Fingerprint for User: {username} ---")
    print("Place your finger on the scanner (simulated)...")
    time.sleep(1)
    fingerprint_uuid = uuid.uuid4()
    fingerprint_template = str(fingerprint_uuid)
    enrolled_fingerprints[username] = fingerprint_template
    print(f"Fingerprint enrolled successfully for user: {username}")
    print(f"Simulated Fingerprint UUID Template: {fingerprint_template}")
    return True

def authenticate_fingerprint(username):
    print(f"\n--- Authenticating User: {username} ---")
    if username not in enrolled_fingerprints:
        print(f"User '{username}' not enrolled. Authentication failed.")
        return False
    print("Place your finger on the scanner for verification (simulated)...")
    time.sleep(1)
    entered_uuid_str = input("Enter the Simulated Fingerprint UUID for Verification: ")
    stored_template = enrolled_fingerprints[username]
    if entered_uuid_str == stored_template:
        print(f"Fingerprint authenticated successfully for user: {username} (UUID verification simulated)!")
        return True
    else:
        print("Fingerprint authentication failed: UUID Mismatch.")
        return False

def main():
    while True:
        print("\n--- Biometric Fingerprint Authentication Simulation (UUID) ---")
        print("1. Enroll User Fingerprint")
        print("2. Authenticate User Fingerprint")
        print("3. Exit")
        choice = input("Enter your choice (1-3): ")
        if choice == '1':
            username_enroll = input("Enter username to enroll: ")
            if username_enroll:
                enroll_fingerprint(username_enroll)
            else:
                print("Username cannot be empty for enrollment.")
        elif choice == '2':
            username_auth = input("Enter username to authenticate: ")
            if username_auth:
                authenticate_fingerprint(username_auth)
            else:
                print("Username cannot be empty for authentication.")
        elif choice == '3':
            print("Exiting simulation.")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()