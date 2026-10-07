#auth with mock db imported from users.AttributeErrorjson

import json
import argon2
from argon2.exceptions import VerifyMismatchError

ph = argon2.PasswordHasher()

failure_tracker={}

#loading db from json
def load_db():
    try:
        with open("users.json","r") as f:
            return json.load(f)
        
    except FileNotFoundError:
        return{} #returns nothing as no file
    
def save_db(db):
    with open("users.json", "w") as f:
        json.dump(db, f, indent=4)
    
#initialise database
mock_db=load_db()




def login(user,password):
    #check if user exists
    if user not in mock_db:
        print("Access Denied")
        return None
    
    #check lockout status
    if failure_tracker.get(user,0) >=5:
        print(f"Access Denied: '{user}' is locked due to too many wrong attempts")
        return "Locked"
    
    try:
        stored_hash = mock_db[user]["hash"]
        ph.verify(stored_hash,password)

        #reset failure when successful login
        failure_tracker[user]=0

        if ph.check_needs_rehash(stored_hash):
            mock_db[user]["hash"] = ph.hash(password)
            save_db(mock_db)

        return mock_db[user]["role"]
        
    except VerifyMismatchError:
        failure_tracker[user]=failure_tracker.get(user,0)+1
        print(f"Invalid Password. Attempt {failure_tracker[user]} out of 5")
        return None


if __name__=="__main__":
    #test 1: successful login
    print("Test 1: Successful Student Login")
    role = login("mock_student", "password123")
    print(f"Result: Access Granted as {role}")

    #test 2: incorrect password
    print("Test 2: Incorrect Password")
    login("mock_student", "wrongpassword") 

    #test 3: resetting password attempts
    print("Test 3: Resetting Attempts on Successful Login")
    role=login("mock_student", "password123")
    print("Successful Login and Reset of Attempts")

    #test 4: brute force test
    print("Test 4: 5 Attempt Account Lockout")
    for i in range(5):
        login("mock_student", "bruteforceattack") #should show each failed attempt
        
    print("Attempting correct password after 5 failures:")
    login("mock_student", "password123") #should still say "Locked"

    #test 5: invalid user
    print("Test 5: Invalid User")
    login("invalid_user", "password123")



