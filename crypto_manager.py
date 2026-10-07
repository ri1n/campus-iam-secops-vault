#aes-256
#hmac-sha256
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


KEY_FILE = "secret.key"

#generates key only if doesnt already exist
def initialise_key():
    if not os.path.exists(KEY_FILE):
        key=Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)

#retrieves key
def load_key():
    return open(KEY_FILE, "rb").read()

#encrypts file and replaces original
def protect_file(filepath, key):
    f=Fernet(key)
    with open(filepath, "rb") as file:
        data = file.read()

        encrypted_data = f.encrypt(data)
        with open(filepath+".enc","wb") as file:
            file.write(encrypted_data)

    #remove unencryoted original
    #os.remove(filepath)


def run_crypto_tests():
    initialise_key()

    key=load_key()

    print(f"System intialised. Key loaded from {KEY_FILE}")

    ###TESTING
    #DUMMY TEST FILE
    with open("test_grades.json", "w") as f:
        f.write('{"Alvin":"F", "Simon":"A", "Theodore":"D"}')

    #protect the file
    protect_file("test_grades.json", key)
    print("File encrypted successfully as test_grades.json.enc")



if __name__=="__main__":
    run_crypto_tests()


#decrypt file for viewing
def access_file(encrypted_path, key):
    f=Fernet(key)
    with open(encrypted_path, "rb") as file:
        encrypted_data = file.read()

    #return original data or show error if tampered with
    return f.decrypt(encrypted_data).decode()


#digital signatures

SYSTEM_PRIVATE_KEY_FILE = "system_private.pem"
SYSTEM_PUBLIC_KEY_FILE = "system_public.pem"

def generate_system_signing_keys():

    #generate if keys dont exist
    if not os.path.exists(SYSTEM_PRIVATE_KEY_FILE):
        print("Generating system-wide signing keys")

        #generates rsa keys for digital signatures
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        #save private key
        with open(SYSTEM_PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        #save public key
        with open(SYSTEM_PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print(f"Keys saved to {SYSTEM_PRIVATE_KEY_FILE} and {SYSTEM_PUBLIC_KEY_FILE}")
        
        return private_key, public_key
        
    else:
        print("System keys already exist")
        return load_system_signing_keys()

def load_system_signing_keys():
    #load priv key
    with open(SYSTEM_PRIVATE_KEY_FILE, "rb") as f:
        private_key=serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    #load pub key
    with open(SYSTEM_PUBLIC_KEY_FILE,"rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read()
        )
    return private_key, public_key


def sign_data_system(data_string):
    #sign grades string to prove authenticiyy
    private_key, _ = load_system_signing_keys()
    signature = private_key.sign(
        data_string.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
    )

    #save sig to file
    with open("grades.sig", "wb") as f:
        f.write(signature)
    return signature

#check grades havent been changed
def verify_signature_system(data_string):
    try:
        _, public_key = load_system_signing_keys()
        with open("grades.sig", "rb") as f:

            signature=f.read()
        public_key.verify(
            signature,
            data_string.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False






#key rotation
def rotate_system_key(filepath):
    #decrypt data
    old_key = load_key()
    raw_data=access_file(filepath, old_key)

    #create and save new key
    new_key=Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(new_key)

    #re encrypt new key
    temp_file = "temp_rotate.json"
    with open(temp_file, "w") as f:
        f.write(raw_data)

    protect_file(temp_file, new_key)
    os.replace(temp_file + ".enc", filepath)
    os.remove(temp_file)
    return new_key
