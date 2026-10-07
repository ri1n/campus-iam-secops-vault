#argon2 login
# rbac logic



#python argon2-cffi

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

#initialise hasher
ph=PasswordHasher()

#dictionary to track failed attempts
failed_attempts = {}


#hashes password
def hash_user_password(password):
    return ph.hash(password)

#verify login and failed attempts
def verify_login(stored_hash, provided_password, username):
    #checks 5 attempt lockout
    if failed_attempts.get(username, 0) >=5:
        return "Too many incorrect attempts"
    
    try:
        #Attempt verification
        