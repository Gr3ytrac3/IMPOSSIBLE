import hashlib

def generate_hashes(password: str):
    class HashGenerator:
        def __init__(self, password: str):
            self.password = password.encode()

        def generate(self):
            return {
                "MD5": hashlib.md5(self.password).hexdigest(),
                "SHA1": hashlib.sha1(self.password).hexdigest(),
                "SHA256": hashlib.sha256(self.password).hexdigest(),
                "SHA512": hashlib.sha512(self.password).hexdigest(),
            }

    hashes = HashGenerator(password).generate()
    return hashes

if __name__ == "__main__":
    pwd = input("Enter a password: ")
    results = generate_hashes(pwd)
    print("Generated Hashes:")
    # Note: Hashes like MD5, SHA1, SHA256, and SHA512 are cryptographic hash functions and are designed to be one-way.
    # It is not possible to "decipher" or reverse them to get the original password.
    # If you want to check if a password matches a hash, you can compare the hash of the input to the stored hash.
    # Example:
    # input_hash = results["MD5"]
    # check_pwd = input("Enter password to check: ")
    # if hashlib.md5(check_pwd.encode()).hexdigest() == input_hash:
    #     print("Password matches the MD5 hash.")
    # else:
    #     print("Password does not match the MD5 hash.")
    for algo, h in results.items():
        print(f"{algo}: {h}")
