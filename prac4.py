import hashlib  # For hashing algorithms

def crack_password_dictionary(password_hash, dictionary_file="dictionary.txt"):
    """
    Performs a dictionary attack to crack a password hash.

    Args:
        password_hash (str): The hash of the password to crack.
        dictionary_file (str, optional): Path to the dictionary file. Defaults to "dictionary.txt".

    Returns:
        str or None: The cracked password if found in the dictionary, otherwise None.
    """
    try:
        with open(dictionary_file, "r") as dict_file:
            for word in dict_file:
                word = word.strip()  # Remove newline characters
                hashed_word = hashlib.sha256(word.encode('utf-8')).hexdigest() # Using SHA256 for example

                if hashed_word == password_hash:
                    print(f"[+] Password cracked! Found: {word}")
                    return word
        print("[-] Password not found in the dictionary.")
        return None

    except FileNotFoundError:
        print(f"Error: Dictionary file '{dictionary_file}' not found.")
        return None


def generate_hash(password):
    """Generates a SHA256 hash of a given password (for demonstration)."""
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return hashed_password


def main():
    """Main function to demonstrate offline password cracking."""

    print("--- Basic Offline Password Cracking (Dictionary Attack) ---")
    print("WARNING: Use this for ethical and educational purposes ONLY!")
    print("         Unauthorized password cracking is illegal and unethical.\n")

    # Example: Let's create a sample password hash to crack (you would get this from a system)
    example_password = "password12345"
    example_hash = generate_hash(example_password)
    print(f"[Example] Target Password Hash to crack: {example_hash}")

    # You can replace "dictionary.txt" with a path to a larger dictionary file if you have one
    dictionary_file_path = "dictionary.txt" # Or "/path/to/your/wordlist.txt"

    cracked_password = crack_password_dictionary(example_hash, dictionary_file_path)

    if cracked_password:
        print(f"Cracked Password: {cracked_password}")
    else:
        print("Password cracking attempt failed.")


if __name__ == "__main__":
    # Create a very small example dictionary file (dictionary.txt) in the same directory as the script
    # This is for demonstration only. Real dictionaries are much larger.
    with open("dictionary.txt", "w") as f:
        f.write("password\n")
        f.write("password12345\n")
        f.write("123456\n")
        f.write("qwerty\n")
        f.write("admin\n")
        f.write("secret\n")
        f.write("test\n")
        f.write("apple\n")
        f.write("banana\n")
        f.write("orange\n")


    main()