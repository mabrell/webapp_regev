import random
import numpy as np
import math

def gen(security_param):
    n = security_param
    q = int(round(40*n))
    sk = np.matrix([random.randint(0,q)])
    for i in range(n- 1):
        temp = random.randint(0,q)
        sk = np.insert(sk,0, temp, axis = 0)

    m = round(2 * n * round(math.log(q)))

    a_starter = np.array([random.randint(0,q)])
    for i in range(m- 1):
        temp = random.randint(0,q)
        a_starter = np.append(a_starter, temp)
        
    #Creation of matrix A, starting off with a starter column


    A =  np.matrix(a_starter.reshape(m, 1))
    for k in range(n - 1): #Adding new columns onto the matrix
        temp_vector = np.array([random.randint(0,q)])
        for i in range(m - 1):
            temp = random.randint(0,q)
            temp_vector = np.append(temp_vector, temp)

        A = np.insert(A, 0, temp_vector, axis = 1)

    #Discrete Gaussian Error Generator - currently uniform
    e = np.matrix([random.randint(0,2)])
    for i in range(m-1):
        temp2 = abs(random.randint(0,2))
        e = np.insert(e,0 ,temp2, axis = 0)    


    
    #y calculation
    y = np.add((np.dot( A, sk) % q),e)


    #public key generation
    pk = [A, y]


    return(pk, sk)



def enc(pk, u): #where u is the message, only messages of 0 or 1 are allowed
    r = np.matrix([random.randint(0,1)])
    A, y = pk
    m = A.shape[0]
    n = A.shape[1]
    q = int(round(40*n))
    for i in range(m-1):
        r = np.insert(r, 0, random.randint(0,1), axis = 1)
    
    b_product = np.dot(r, y)
    b_int_product = int( b_product[0,0]) % q
    
    a = np.dot( r, A) % q
    b = round((b_int_product + u * round(q/2)) % q)

    return a,b #returns the ciphertext


def dec(sk, c): #where c is the ciphertext
    a,b = c
    n = a.shape[1]
    q = int(round(40*n))
    y_errorless_reconstruct = np.dot(a,sk)[0,0] % q
    result = abs((b - y_errorless_reconstruct) % q) 
    
    if (result < (q/4)):
        return 0
    else:
        return 1
    


def string_to_binary(input_string): 
    binary_result = ''
    for char in input_string:
        binary_result = binary_result + format(ord(char), '08b')

    return binary_result


def binary_to_string(binary_string): # Split the binary string into 8-bit chunks (since each ASCII character is represented by 8 bits) 
    n = 8 
    chunks = [binary_string[i:i+n] for i in range(0, len(binary_string), n)] #
    ascii_chars = [chr(int(chunk, 2)) for chunk in chunks] 
    ascii_string = ''.join(ascii_chars) 
    return ascii_string



def bit_string_enc(pk, message):
    full_cipher_a_matrix = []
    full_cipher_b_vector = []
    cipher_started = False
    
    for digit in message:
        int_digit = int(digit)
        a, b = enc(pk, int_digit)
        if cipher_started == False:
            full_cipher_a_matrix = a
            full_cipher_b_vector = np.matrix([b])
            cipher_started = True
        else:
            full_cipher_a_matrix = np.insert(full_cipher_a_matrix, 0, a, axis = 0) #This creates a matrix with the top row being the last encryption, bottom row being the first
            full_cipher_b_vector = np.insert(full_cipher_b_vector, 0, np.matrix([b]), axis = 1) #This creates a vector with the leftmost element being the last encryption, the rightmost being the first encryption


    return full_cipher_a_matrix, full_cipher_b_vector




def bit_string_dec(sk, c):
    full_cipher_a_matrix, full_cipher_b_matrix = c
    message = []
    for i in range(np.shape(full_cipher_b_matrix)[1]):
        a = full_cipher_a_matrix[i,]
        b = full_cipher_b_matrix[0,i]
        temp_c = a,b
        current_result = dec(sk, temp_c)
        message = np.insert(message, 0, int(current_result))
    
    
    int_message = list(map(int, message))
    str_message = list(map(str, int_message))
    full_str_message = ''.join(str_message)
    print(f"pre-translation, post decryption: {full_str_message}")
    return full_str_message


def string_enc(pk, message):
    bit_string_message = string_to_binary(message)
    return bit_string_enc(pk, bit_string_message)
    
def string_dec(sk, c):
    result = bit_string_dec(sk, c)
    message = binary_to_string(result)
    print(f"decrypted message: {message}")
    return message


def secret_key_input_reformatter(secret_key_raw): 
    past_1 = False
    counter = 0
    internal_clock = 0
    while (secret_key_raw[counter] != ';'):
                current_string = ''
                while (secret_key_raw[counter] != ',') & (secret_key_raw[counter] != ';'):
                    current_string = current_string + secret_key_raw[counter]
                    counter += 1
                
                current_string = int(current_string)

                if past_1 == False:
                    current_vector = np.matrix([current_string])
                    internal_clock += 1
                    past_1 = True
                else:
                    current_vector = np.insert(current_vector, internal_clock, int(current_string), axis = 0 )
                    internal_clock += 1
                if secret_key_raw[counter] == ',':
                    counter += 1

    return current_vector


def public_key_input_reformatter(public_key_raw):
    pkr = public_key_raw
    counter = 0
    stage = 0
    n = ''
    first = True

    while (pkr[counter] != ';'):
        if (stage == 0):
            n = n + pkr[counter]
            counter += 1
    n = int(n)
    counter += 1
    stage += 1
    
    q = int(round(40*n))

    m = round(2 * n * round(math.log(q)))
    
    while (stage != m+5):

        current_vector = np.matrix([])
        if (stage>0) & (stage<m+1):
            internal_clock = 0
            while (pkr[counter] != ';'):
                current_string = ''
                while (pkr[counter] != ',') & (pkr[counter] != ';'):
                    current_string = current_string + pkr[counter]
                    counter += 1

                current_string = int(current_string)
                current_vector = np.insert(current_vector, internal_clock, int(current_string), axis = 1 )
                internal_clock += 1
                if pkr[counter] == ',':
                    counter += 1
            if first == True:
                A = current_vector
                first = False
                stage += 1
                counter += 1
            else:
                A = np.insert(A, stage - 1 , current_vector,  axis = 0)
                stage += 1
                counter += 1
        else:

            first = True
            internal_clock = 0
            while (pkr[counter] != ';'):
                current_string = ''
                while (pkr[counter] != ',') & (pkr[counter] != ';'):
                    current_string = current_string + pkr[counter]
                    counter += 1
                    

                current_string = int(current_string)
                if first == True:
                    y = np.matrix([current_string])
                    first = False
                    internal_clock += 1
                else:
                    y = np.insert(y, internal_clock, int(current_string), axis = 0 )
                    internal_clock += 1
                if pkr[counter] == ',':
                    counter += 1
            stage += 1
            break
    
    return A, y


def public_key_output_reformatter(pk):
    A, y = pk
    n = A.shape[1]
    m = A.shape[0]
    output = ''
    output = output + str(n) + ';'
    for i in range(m):
        for k in range(n):
            output = output + str(A[i, k])
            if k == n-1:
                output = output + ';'
            else:
                output = output + ','

    for p in range(m):
        if p == m-1:
            output = output + str(y[p,0])
        else:
            output = output + str(y[p,0]) + ','
    output = output + ';'

    return output
    
def secret_key_output_reformatter(sk):
    output = ''
    for p in range(sk.shape[0]):
        if p == sk.shape[0]-1:
            output = output + str(sk[p,0])
        else:
            output = output + str(sk[p,0]) + ','
    output = output + ';'
    return output


#This function intakes the amalgamated ciphertext (a matrix and a vector) and outputs it according to the format:
# n; [row1 seperated by commas]; [row2]; [row3];....;[row m]; [y vector seperated by commas];

def cipher_text_output_reformatter(c):
    A, y = c
    n = A.shape[1]
    l = A.shape[0] #Where l is 8 * # of characters in the message
    output = ''
    output = output + str(n) + ';'
    for k in range(l):
        for i in range(n):
            output = output + str(A[k, i])

            if i == n - 1:
                output = output + ';'
            else:
                output = output + ','

    for p in range(l):
        if p == l-1:
            output = output + str(y[0,p])
        else:
            output = output + str(y[0,p]) + ','
    output = output + ';'

    return output


#This function takes as input the ciphertext in external form (i.e. as a copy/pastable string) 
#and returns it as A and y, the matrix and vector amalgamation of a set of ciphertexts.

def cipher_text_input_reformatter(c):
    pkr = c
    counter = 0
    stage = 0
    n = ''
    first = True

    while (pkr[counter] != ';'):
        if (stage == 0):
            n = n + pkr[counter]
            counter += 1
    n = int(n)
    counter += 1
    stage += 1
    
    q = int(round(40*n))
    loop = True
    reached_second_cipher = False
    stored_vector = np.matrix([])
    while (loop == True):
        
        current_vector = np.matrix([])
        if (reached_second_cipher == False):
            internal_clock = 0
            while (pkr[counter] != ';') and (reached_second_cipher == False):
                current_string = ''
                while (pkr[counter] != ',') & (pkr[counter] != ';'):
                    current_string = current_string + pkr[counter]
                    counter += 1

                current_string = int(float(current_string))
                


                current_vector = np.insert(current_vector, internal_clock, int(current_string), axis = 1 )
                
                internal_clock += 1
                if (internal_clock -1 > n):
                    reached_second_cipher = True
                    stored_vector = current_vector
                    break
                if pkr[counter] == ',':
                    counter += 1
            if (first == True) and (reached_second_cipher == False):
                A = current_vector
                first = False
                stage += 1
                counter += 1
            elif (reached_second_cipher == False):
                A = np.insert(A, stage - 1 , current_vector,  axis = 0)
                stage += 1
                counter += 1
        else:

            current_vector = stored_vector
            counter += 1
            while (pkr[counter] != ';'):
                current_string = ''

                while (pkr[counter] != ',') & (pkr[counter] != ';'):
                    current_string = current_string + pkr[counter]
                    counter += 1
                    

                current_string = int(current_string)

                current_vector = np.insert(current_vector, internal_clock, int(current_string), axis = 1 )
                internal_clock += 1

                if pkr[counter] == ',':
                    counter += 1
            stage += 1
            break
    
    return A.astype(int), current_vector

