# Implementation to original method of Yao's Millionaires' Problem.
# http://www.matrix67.com/blog/archives/1362

# Configurations
score_limit = {  # Score is an integer between [low, up]
    "up": 10,
    "low": 1
}
SMALL_P_LENGTH = 48

dash = '----------------------------------------'
e = 65537

import random
import socket
from fastSerialize import *
from fastpow import pow

try:
    from Crypto.Util import number
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
except ModuleNotFoundError:
    print(
        'You have not install pycryptodome.\n',
        'Try typing the following command in your shell:\n',
        '    > pip install pycryptodome\n',
        'to install pycryptodome and come back again.',
        sep=''
    )
    exit(1)

class RandomNumbers:
    __slots__ = ('l', 'p')

    def __init__(self, l, p):
        assert len(l) == score_limit['up'] - score_limit['low'] + 1
        self.l, self.p = l, p

    @classmethod
    def from_list(cls, l):
        score_num = score_limit['up'] - score_limit['low'] + 1
        assert len(l) == score_num + 1
        return cls(l[:-1], l[-1])

    def to_list(self):
        l = self.l[:]
        l.append(self.p)
        return l

def role_a_generator(score, encoded_number):
    '''
    :param score: An integer between [0, limit.up - limit.low].
    :param encoded_number: Serialized public key.
    :yield: Encrypted score
    :receive: Long code
    :yield:
        '<partner' when score is smaller than another participant.
        '>=partner' otherwise.
    :return: None
    '''

    # Decode B's public key
    N = fast_load(encoded_number)[0]

    # Generate a random number with same length as N
    n_len = N.bit_length()
    while True:
        rand: int = random.getrandbits(n_len)
        if rand.bit_length() >= n_len - 1 and rand < N:
            break

    # encrypt (cipher - score) and send
    cipher = pow(rand, e, N)
    long_code = yield fast_dump([cipher - score])

    rn = RandomNumbers.from_list(
        fast_load(long_code)
    )

    # If smaller than partner, rn.l[score] should exactly the same as rand
    if rn.l[score] == rand % rn.p:
        yield '<partner'
    else:
        yield '>=partner'

def role_b_generator(score):
    '''
    :param score: An integer between [0, limit.up - limit.low].
    :yield: Serialized public key.
    :receive: Encrypted score
    :yield: Long code
    :return: None
    '''
    # Generate RSA public key
    key = RSA.generate(1024)
    N, d = key.n, key.d

    # Share the public number N, receive (cipher - a_score)
    enc_score = yield fast_dump([N])
    enc_score = fast_load(enc_score)[0]

    # Generate a list, and mutate part of it
    l = [pow(enc_score + i, d, N)
         for i in range(score_limit['up'] - score_limit['low'] + 1)]
    for i in range(score, len(l)):
        l[i] += 1

    # Remove extra info by mod a random prime, and share the list
    p = number.getPrime(SMALL_P_LENGTH)
    rnd_nums = RandomNumbers(
        [x % p for x in l], p
    )
    yield fast_dump(rnd_nums.to_list())

def input_score(prompt):
    res = int(input(prompt))
    if res < score_limit['low'] or res > score_limit['up']:
        raise ValueError(f'Must be in range [{score_limit["low"]}, {score_limit["up"]}]')
    return res - score_limit['low']

def println(*args):
    for i in args:
        print(i)

def role_a(generator_a):
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind(('',5000))
    s.listen(1)
    println("Waiting for B to connect... ")
    c,addr=s.accept()
    score = input_score('Step 1. Input your score: ')
	
    println('', 'Step 2. Receive a encoded number from B.')
    gen = generator_a(score, c.recv(1024).decode())
    v=gen.send(None)
    println('', 'Step 3. Send encrypted score to B.',
            dash, v, dash)
    c.send(v.encode())

    println('', 'Step 4. Receive a long code from B.')
    result = gen.send(c.recv(1024).decode())

    if result == '<partner':
        println('', dash, "Your score < Partner's score")
        message="Your score >= Partner's score"
        c.send(message.encode())
    else:
        println('', dash, "Your score >= Partner's score")
        message="Your score < Partner's score"
        c.send(message.encode())

def role_b(generator_b):
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(('127.0.0.1',5000))
    score = input_score('Step 1. Input your score: ')

    gen = generator_b(score)
    v=gen.send(None)
    println('', 'Step 2. Copy the encoded number and send to A:',
            dash, v, dash)
    s.send(v.encode())
	

    println('', 'Step 3. Receive encrypted score from A.')
    long_code = gen.send(s.recv(1024).decode())

    println('', 'Step 4. Send those long codes to A, then ask for result.',
            dash, long_code, dash)
    s.send(long_code.encode())
    println(s.recv(1024).decode())

def select_role():
    print(
        'Please select your role.\n',
        'You and your partner must choose different roles.\n',
        '[A] Role A\n',
        '    Knows the final result.\n',
        '[B] Role B\n',
        '    Has to ask role A about the result.\n',
        sep=''
    )

    res = input('Your choice: ').upper()
    if res != 'A' and res != 'B':
        raise ValueError('You must input A or B.')
    return res

def main():
    role = select_role()
    print('')
    if role == 'A':
        return role_a(role_a_generator)
    else:
        return role_b(role_b_generator)

if __name__ == '__main__':
    main()