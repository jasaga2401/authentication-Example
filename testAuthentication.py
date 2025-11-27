def outputResult(status):
    if (status == True):
        print('Access allowed')
    else:
        print('Access notallowed')

def checkValid(username, passwd):
    if (username == 'admin' and passwd == 'Password123'):
        return True
    else:
        return False

def inputUserPass():
    user = input('What is your username?')
    passwd = input('What is your password?')
    return user, passwd

def main():
    us, pswd = inputUserPass()
    status = checkValid(us, pswd)
    outputResult(status)

if (__name__ == "__main__"):
    main()
