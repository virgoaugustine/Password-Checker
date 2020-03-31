import requests
import hashlib


def data_from_api(first_five_chars):
    '''
    Input: The first five characters of the SHA-1 encrypted password to check.

    Output: An object that contains all hashes in the database that match the input of this function.
    '''
    url = 'https://api.pwnedpasswords.com/range/' + first_five_chars
    result = requests.get(url)

    if result.status_code != 200:
        raise RuntimeError(f'Error: {result.status_code}. Please try again')

    return result

def leaked_password_count(result, rest_of_chars):
    '''
    Input1: The result received from the 'data_from_api' function.
    Input2: The latter part of the hashed_password.

    Output: The number of times a password was leaked.
    '''
    hashes = [line.split(':') for line in result.text.splitlines()]
    #used h instead of hash because hash is a default method.
    for h, count in hashes:
        if h == rest_of_chars:
            return count
    return 0


def check_password(password):
    '''
    Input: Password to check

    Output: leaked_password_count.
    '''
    #convert password to SHA-1 
    hashed_password = hashlib.sha1(password.encode()).hexdigest().upper()
    first_five_chars, rest_of_chars = hashed_password[:5], hashed_password[5:]

    result = data_from_api(first_five_chars)
    

    return leaked_password_count(result, rest_of_chars)
    
    
def main():
    password = str(input('Enter the password to check: '))
    leak_count = check_password(password)

    if int(leak_count) > 0:
        print(f'The password "{password}" was leaked {leak_count} times. You should probaly change your password.')
    else:
        print(f'The password "{password}" has never been leaked.')

    return 'Done!'
    

if __name__ == '__main__':
    print(main())