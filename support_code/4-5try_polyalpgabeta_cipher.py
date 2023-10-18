import numpy as np

letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
A = np.array([[3, 5], [1, 2]])
b = np.array([2, 3])


def encrypt(plaintext):
    cipher = ""
    for i in range(0, len(plaintext), 2):
        first_letter = plaintext[i]
        second_letter = plaintext[i + 1]
        p_1 = letters.find(first_letter)
        p_2 = letters.find(second_letter)
        p = np.array([p_1, p_2])
        cipher_vector = np.dot(A, p) + b
        c_1 = cipher_vector[0] % 26
        c_2 = cipher_vector[1] % 26
        cipher += letters[c_1]
        cipher += letters[c_2]
    return cipher

def decrypt(cipher):
    A_inverse = np.array([[2, -5], [-1, 3]])
    plaintext = ""
    for i in range(0, len(cipher), 2):
        first_letter = cipher[i]
        second_letter = cipher[i + 1]
        c_1 = letters.find(first_letter)
        c_2 = letters.find(second_letter)
        c = np.array([c_1, c_2])
        plaintext_vector = np.dot(A_inverse, c) - np.dot(A_inverse, b)
        p_1 = plaintext_vector[0] % 26
        p_2 = plaintext_vector[1] % 26
        plaintext += letters[p_1]
        plaintext += letters[p_2]
    return plaintext

print(encrypt("HELPSAVEME"))
print(decrypt("RSGSEVHGGX"))