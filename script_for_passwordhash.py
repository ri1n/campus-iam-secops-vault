import argon2
ph=argon2.PasswordHasher()
#student
print(ph.hash("password123"))
#admin
print(ph.hash("password456"))
#lecturer
print(ph.hash("password789"))