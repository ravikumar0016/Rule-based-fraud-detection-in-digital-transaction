#!/usr/bin/env python
# coding: utf-8

# # Fraud detection in digital transaction
# ### ravirajchaurasiya111@gmail.com

# In[ ]:


import re
import string
# Database connection
import mysql.connector

conn = mysql.connector.connect(
  host="localhost",
  user='root',
  password='1234',
  database='16bit0016'
)

# Account variables
accountno = int(input('enter account no.:->'))
amount = float(input('enter ammount to withdraw:->'))
countrylocation = input('enter country:->')
statelocation = input('enter state:->')
TranNo=int(input('enter the transaction no. of the day:->'))
# FRAUD------------------------------------------------------------------------------------------------------------------------------
# cursor to fetch from database
mycursor = conn.cursor(buffered=True)
# function to detect amount fraud
def amountfraud():
    mycursor.execute("select  MAX(Withdrawal_INR) from accountstatement where AccountNo=%s", (accountno,))
    maxwithdrawal=mycursor.fetchone()
    expextedamount=(1.5*maxwithdrawal[0])

    if amount > expextedamount:
        return True
    else:
        return False
# function to detect country_location fraud
def countryfraud():
  mycursor.execute("SELECT Location_Country FROM accountstatement WHERE AccountNo=%s and Location_Country=%s ",(accountno, countrylocation,))
  Con_location = mycursor.fetchall()
  #print(Con_location)
  if len(Con_location) == 0:
    return True
  else:
    return False
# function to detect State_location fraud
def statefraud():
    mycursor.execute("SELECT Location_State FROM accountstatement WHERE AccountNo=%s and Location_state=%s ",(accountno, statelocation,))
    State_location = mycursor.fetchall()
    #print(State_location)
    if len(State_location)==0:
        return True
    else:
        return False
# function to detect frequent transaction fraud
def frequenttransactionfraud():

  mycursor.execute("SELECT COUNT(TranDate) as count FROM accountstatement where AccountNo=%s GROUP BY TranDate ORDER BY count DESC", (accountno,))
  maxfreq=mycursor.fetchone()
  maxfrequency=maxfreq[0]
  if maxfrequency<=15:
    expectedfrequency=15
  elif maxfrequency>15 and maxfrequency<=30:
    expectedfrequency=int(1.5*maxfrequency)
  elif maxfrequency>30 and maxfrequency<=50:
    expectedfrequency=int(1.6*maxfrequency)
  elif maxfrequency>50 and maxfrequency<=100:
    expectedfrequency=int(maxfrequency*2)
  elif maxfrequency>100 and maxfrequency<=500:
    expectedfrequency=int(maxfrequency*2.5)
  elif maxfrequency>500 and maxfrequency<=1000:
    expectedfrequency=int(maxfrequency*5)
  else:
    expectedfrequency=int(5*maxfrequency)

  if TranNo > expectedfrequency:
    return True
  else:
    return False
# function to get cipher key from database
def getcipherkey():
  mycursor.execute("select Cipher_key from privacy_details where AccountNo=%s", (accountno,))
  sec_key = mycursor.fetchone()
  cipher_key = sec_key[0]
  return cipher_key
# function to get ATMPIN from database
def getatmpin():
  mycursor.execute("select Atm_PIN from privacy_details where AccountNo=%s", (accountno,))
  atmpin= mycursor.fetchone()
  Atm_PIN=atmpin[0]
  return Atm_PIN

# cipher -------------------------------------------------------------------------------------------------------

alphabets = "abcdefghijklmnopqrstuvwxyz" # this is the english letters
# function to encrypt using vigenere cipher
def vigenere_encrypt(p, k):
    c = ""
    kpos = [] # return the index of characters ex: if k='d' then kpos= 3
    for x in k:
       # kpos += alphabets.find(x) #change the int value to string
        kpos.append(alphabets.find(x))
    i = 0
    for x in p:
      if i == len(kpos):
          i = 0
      pos = alphabets.find(x) + kpos[i] #find the number or index of the character and perform the shift with the key
      #print(pos)
      if pos > 25:
          pos = pos-26               # check you exceed the limit
      c += alphabets[pos].capitalize()  #because the cipher text always capital letters
      i +=1
    return c
# # function to decrypt using vigenere cipher
def vigenere_decrypt(c, k):
    p = ""
    kpos = []
    for x in k:
        kpos.append(alphabets.find(x))
    i = 0
    for x in c:
      if i == len(kpos):
          i = 0
      pos = alphabets.find(x.lower()) - kpos[i]
      if pos < 0:
          pos = pos + 26
      p += alphabets[pos].lower()
      i +=1
    return p
# function to encrypt using autokey cipher
def autokey_encrypt(cleartext, key):
    ciphertext = ""
    key = key + cleartext
    i = 0
    while i < len(cleartext):
        ciphertext += __vig(cleartext[i], key[i])
        i += 1
    return ciphertext

# function to decrypt using autokey cipher
def autokey_decrypt(ciphertext, key):
    cleartext = ""
    i = 0
    while i < len(ciphertext):
        cleartext += __vig(ciphertext[i], key[i % len(key)], True)
        key += cleartext[-1]
        i += 1
    return cleartext


def __rot(l, d):
    # Rotate the letter l by the specified number of degrees (assume uppercase)
    return chr((((ord(l) - ord('A')) + d) % 26) + ord('A'))


def __vig(l, k, inverse=False):
    # Determine the index of key-letter 'k' relative to 'A' and use that
    # as the number of degrees to rotate by.
    degree = ord(k) - ord('A')
    if inverse:
        degree = -degree
    return __rot(l, degree)


# main program--------------------------------------------------------------------------------------------------------


def cipherdecrypt(cipherkey,secretkey):
    pt1 = autokey_decrypt(cipherkey,secretkey)
    pt2 = vigenere_decrypt(pt1, secretkey)
    return pt2

if amountfraud()==True or countryfraud()==True or statefraud()==True or frequenttransactionfraud()==True:
    if amountfraud()==True:
        print("AMOUNT REQUEST IS LARGER THAN USUAL\n")
    if countryfraud()==True:
        print("YOUR CURRENT LOCATION IS OUT OF COUNTRY \n")
    else:
        if statefraud() == True:
            print("YOUR STATE LOCATION IS OUT OF RANGE \n")
    if frequenttransactionfraud()==True:
        print("TRANSACTION FREQUENCY CROSSED THE LIMIT\n")
    print("YOUR ACCOUNT IS BLOCKED BECAUSE OF FRAUD DETECTED.\n")
    secretkey=input("Please enter your secret key to unblock:\n")

    # check secret key is  correct or not
    cipherkey = getcipherkey()
    ATMPIN = getatmpin()
    if cipherdecrypt(cipherkey,secretkey)== ATMPIN :
        print("your account is unblocked.Now,you can make transaction.\n")
    else:
        print("WARNING!Incorrect secret key.\n")
        secretkey2=input("Please enter correct secret key:\n")
        if cipherdecrypt(cipherkey,secretkey2)== ATMPIN:
            print("Your account is unblocked.Now, you can make transaction.\n")
        else:
            print("!Again.Incorrect secret key.\n")
            print("contact your bank to unblock your account.\n")

else:
    print("Transaction successful.\n")

