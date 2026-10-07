#key management
import json
import os
import getpass
import datetime
import random
from cryptography.fernet import InvalidToken
from auth_with_json_db import login
from crypto_manager import access_file, load_key, initialise_key, protect_file, rotate_system_key, sign_data_system, verify_signature_system, generate_system_signing_keys


#audit logging
def log_event(user, action):
    timestamp = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    with open("system_audit.log", "a") as f:
        f.write(f"[{timestamp}] User: {user} | Action: {action}\n")

def mfa_logic(user, role):
    #create mfa code
    mfa_code=str(random.randint(100000,999999))
    print(f"A code has been sent to your device (For testing - mfa code: {mfa_code})")

    user_mfa = input("Enter the code: ")
    

    if user_mfa !=mfa_code:
        print("Mfa verification failed")
        log_event(user, "mfa failure")
        return False

    log_event(user, f"Login and MFA Successful - Role: {role}")
    return True
    ##may need to put directly in code*

def main():

    initialise_key()
    #initialise system wide signing keys if doesnt exist
    generate_system_signing_keys()

    while True: ##Loops round so dont have to run file each time

        user=input("Username (or 'q' to quit): ")

        if user.lower()=='q':
            log_event("System", "Application Shutdown")
            break
        password = getpass.getpass("Password: ")


        role = login(user, password)


        if role and role != "Locked":
            if mfa_logic(user, role):
                log_event(user, f"Login Successful - Role: {role}")


                if role == "Admin":
                    while True: ####subloop
                        print(f"Welcome, {role}")
                        print("[1] View All Grades")
                        print("[2] Edit Student Grades")
                        print("[3] View System Audit Log")
                        print("[4] Rotate Crypto Key")
                        print("[q] To quit")

                        choice = input("Choose an option: ")
                        if choice == "1":
                            #view test grades using access_file function
                            key = load_key()

                            try:
                                decrypted_data = access_file("test_grades.json.enc", key)
                                print(f"Student Grades: {decrypted_data}")

                                log_event(user, "Decrypted and viewed grades")
                            
                            except InvalidToken:
                                print("WARNING: DATA INTEGRITY BREACH - FILE HAS BEEN TAMPERED WITH")
                                log_event(user, "Data Integrity Failure")
                            
                            except Exception as e:
                                print(f"Error accessing data: {e}")
                            

                        elif choice =="2":
                            #shows write access lecturer has vs students read only
                            #feature: logic to reencrypt data

                            #decrypt data to get dictionary


                            key = load_key()

                            try:
                                decrypted_data = access_file("test_grades.json.enc", key)
                                grades_dict = json.loads(decrypted_data) #turns string into python dictionary

                                #update grades
                                name = input("Student name: ")
                                new_grade = input("New grade: ")
                                #validation
                                if not name or not new_grade:
                                    print("Name and grade cannot be blank")
                                    continue

                                grades_dict[name] = new_grade

                                updated_json_string=json.dumps(grades_dict)
                                sign_data_system(updated_json_string)

                                print("Digital signature generated")

                            except FileNotFoundError:
                                print("No file found. Creating new one")
                                grades_dict = {}
                            except Exception as e:
                                print(f"Error accessing data: {e}")


                            

                            #save to temp plane file then protect again
                            with open("temp_update.json", "w") as f:
                                json.dump(grades_dict, f)

                            protect_file("temp_update.json", key)

                            #replace old file with new file
                            os.replace("temp_update.json.enc", "test_grades.json.enc")
                            os.remove("temp_update.json")
                            print("Grades updated and database successfully re-encrypted")


                            log_event(user, f"Modified grade for student: {name}")

                        #open audit
                        elif choice == "3":
                            with open("system_audit.log", "r") as f:
                                print(f.read())

                        #rotating key
                        elif choice == "4":
                            print("This will re-encrypt the database")
                            try:
                                rotate_system_key("test_grades.json.enc")
                                print("System key rotated and re-encrypted database successfully")
                                log_event(user, "Performed system key rotation")
                            except Exception as e:
                                print(f"Rotation failed: {e}")



                        elif choice =='q':
                            log_event("System", "Application Shutdown")
                            break



                elif role == "Student":
                    print(f"Welcome, {role} \n You can view your assignments")
                    while True:
                        print("[1] View grades")
                        print("[q] To quit")

                        choice=input("Choose an option: ")
                        if choice == "1":
                            key = load_key()
                            decrypted_data=access_file("test_grades.json.enc", key)
                            grades_dict=json.loads(decrypted_data)

                            if user in grades_dict:
                                print (f"Your grade: {grades_dict[user]}")
                            else:
                                print("No grades found")

                        elif choice == 'q':
                            break
                    

                elif role =="Lecturer":
                    
                    #generate rsa keys for session - now using keys from crypto manager
                    pass

                    while True: #sub loop
                        print(f"Welcome, {role}")
                        print("[1] View All Grades + verify signatures")
                        print("[2] Edit Student Grades + sign")
                        print("[q] To quit")

                        choice = input("Choose an option: ")
                        if choice == "1":
                            #view test grades using access_file function
                            key = load_key()

                            try:
                                decrypted_data = access_file("test_grades.json.enc", key)

                                #verify signature
                                if verify_signature_system(decrypted_data):
                                    print("Data is authentic and signed by lecturer")
                                else:
                                    print("Signature does not match data")


                                print(f"Student Grades: {decrypted_data}")

                                log_event(user, "Decrypted and viewed grades")

                            except InvalidToken:
                                print("WARNING: DATA INTEGRITY BREACH - FILE HAS BEEN TAMPERED WITH")
                                log_event(user, "Data Integrity Failure")
                            except Exception as e:
                                print(f"Error accessing data: {e}")
                            


                        elif choice =="2":
                            #shows write access lecturer has vs students read only
                            #feature: logic to reencrypt data

                            #decrypt data to get dictionary


                            key = load_key()

                            try:
                                decrypted_data = access_file("test_grades.json.enc", key)
                                grades_dict = json.loads(decrypted_data) #turns string into python dictionary

                                #update grades
                                name = input("Student name: ")
                                new_grade = input("New grade: ")

                                if not name or not new_grade:
                                    print("Name and grade cannot be blank")
                                    continue

                                grades_dict[name] = new_grade

                                #turn dict into string
                                updated_json_string = json.dumps(grades_dict)

                                #sign before encryption
                                sign_data_system(updated_json_string)
                                print("Digital signature generated for update")

                                #save to temp plane file then protect again
                                with open("temp_update.json", "w") as f:
                                    f.write(updated_json_string)

                                protect_file("temp_update.json", key)

                                #replace old file with new file
                                os.replace("temp_update.json.enc", "test_grades.json.enc")
                                os.remove("temp_update.json")
                                print("Grades updated and database successfully re-encrypted")


                                log_event(user, f"Modified grade for student: {name}")

                            except Exception as e:
                                print(f"Error accessing data: {e}")






                        elif choice=='q':
                            log_event("System", "Application Shutdown")
                            break


            else:
                print("MFA failed, try again")
                continue

        elif role == "Locked":
            log_event(user, "Login Attempt - Account Locked")
            continue
        else:
        
            log_event(user if user else "Unknown", "Failed Login Attempt")
            continue

                ##have some logic to loop round so doesnt logout each time, eg can view and update grades

main()