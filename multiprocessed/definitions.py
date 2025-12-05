import random
import hashlib as h
import numpy as np

from multiprocessing import shared_memory, Value

success = Value("i",0)

"""Helper function to visualise passwords as hex strings"""


def bytes_to_string(bytes_data):
    intRepresentation = int.from_bytes(bytes_data, "big")
    return "0x{0:x}".format(intRepresentation)
    
"""h(x) - apply only hash function"""


def apply_hash(current, input_size):
    num_bytes = input_size // 8  # INCORRECT I THINK

    current = h.sha1(current).digest()[:num_bytes]
    return current

"""f_i(x) = g_i(h(x)) - apply reduction function unique to table (XOR with table num)
this currently works because last bits are checked for dpt, not first
"""


def apply_reduction(table_id, current, input_size):
    num_bytes = input_size // 8  # INCORRECT I THINK

    table_id = table_id + 1  # makes sure table_id is not 0
    table_id_bytes = table_id.to_bytes(num_bytes, "big")
    current = bytes(x ^ y for x, y in zip(table_id_bytes, current))[:num_bytes]
    return current

"""Generate random password of a given size, hashed NUM_HASHES times"""


def get_random_password(size):
    global NUM_HASHES

    password_gen_incomplete = True
    while password_gen_incomplete:
        new = random.getrandbits(size)
        password = new.to_bytes(num_bytes, "big")

        hashed_value = password
        for i in range(NUM_HASHES):
            if is_dp(password, size):
                print("bad pass!")
                # break     # we're gonna allow generating bad passwords
            hashed_value = apply_hash(hashed_value, size)
            if i == NUM_HASHES - 1:
                password_gen_incomplete = False
        ## if a hashed_value in this loop ends with eight 0s, this password can't be reversed!

    return (password, hashed_value)

"""Generate a list of random hashes to attempt to invert"""


def generate_passwords(num, num_bits):
    my_passwords = list()
    for i in range(num):
        my_passwords.append(get_random_password(num_bits))
    return my_passwords

"""Generate a single random start point, returns the start point alongside empty values for end point and chain
length in the form of a 3 element triple to be stored in the Hellman Table"""


def get_start_point(input_size):
    num_bytes = input_size // 8  # INCORRECT I THINK
    new = random.getrandbits(input_size)
    sp = new.to_bytes(num_bytes, "big")
    return sp

"""Repeatedly call the get_start_point function in order to generate all requiered start points"""


def gen_start_points(num_chains, input_size, hash_data_type):
    num_bytes = input_size // 8  # INCORRECT I THINK
    start_points = [0 for i in range(num_chains)]
    start_points = np.array(start_points, dtype=hash_data_type)

    for i in range(0, num_chains):
        start_points[i] = get_start_point(input_size)

    return start_points

"""Check if a given point is a distinguished point"""


def is_dp(point_in_question, input_size):
    num_bytes = input_size // 8  # INCORRECT I THINK

    last_8_bits_mask = b"\xff"
    for i in range(num_bytes - 1):  # last byte is used for dp
        last_8_bits_mask = b"\x00" + last_8_bits_mask

    masked_val = bytes(
        x & y for x, y in zip(last_8_bits_mask, point_in_question)
    )[:num_bytes]
    if int.from_bytes(masked_val, "big") == 0:  ## ends with 8 0s
        return True
    return False

"""Calculate the end point for a given start point"""


def get_end_point(start_point, chain_length, input_size, table_id):
    current = start_point
    for i in range(0, chain_length):
        if is_dp(current, input_size):
            current = apply_reduction(table_id, current, input_size)
            continue

        current = apply_hash(current, input_size)
    return current

"""Generate the specified number of end points and also removes duplicate rows."""


def gen_end_points(
    start_points, chain_length, input_size, hash_data_type, table_id
):
    num_bytes = input_size // 8  # INCORRECT I THINK

    duplicates_exist = True
    num_chains = len(start_points)

    end_points = [0 for i in range(num_chains)]
    end_points = np.array(end_points, dtype=hash_data_type)

    for i in range(0, num_chains):
        end_points[i] = get_end_point(
            start_points[i], chain_length, input_size, table_id
        )

    return start_points, end_points

"""Generate start points and endpoints for a given table """
def gen_table(hash_data_type, no_chains, hash_size, chain_len, table_id):

    current_start_points = gen_start_points(
        no_chains, hash_size, hash_data_type
    )
    current_start_points, current_end_points = gen_end_points(
        current_start_points,
        chain_len,
        hash_size,
        hash_data_type,
        table_id,
    )

    return current_start_points, current_end_points, table_id

"""Method to recalculate chain up to a specified stop point"""


def find_chain_entry(
    table_id, chain_number, stop_point, start_points, input_size
):
    current = start_points[table_id][chain_number]
    for i in range(stop_point):
        if is_dp(current, input_size):
            current = apply_reduction(table_id, current, input_size)
        current = apply_hash(current, input_size)
    return current

"""Method to tell us if a password guess would have been reduced during calculation and can't be reversed"""
def would_be_reduced(password_guess, input_size, NUM_HASHES):
    for i in range(NUM_HASHES):
        if is_dp(password_guess, input_size):
            return True, password_guess
        password_guess = apply_hash(password_guess, input_size)

    return False, ""

def init_shared_bool(success_var):
    global success

    success = success_var

"""Method to search through the chains of the dpt tables, returns true or false and
the number of collisions / false alarms that occurred and the password guess(if it succeeds)"""
def search_chains(
    tp,
    y,
    start_points,
    end_points,
    table_id,
    no_chains,
    chain_length,
    input_size,
    NUM_HASHES,
):
    global success
    
    true_password = tp
    hash_of_password = y  # assume hash is somewhere in a chain
    false_alarms = 0
    gen_hashes = 0
    false_alarm_hashes = 0
    success_hashes = 0

    # the last NUM_HASHES in the chain are irrelevant to us, since we cannot reverse back to them
    for i in range(0, chain_length - NUM_HASHES):
        # search endpoints for hash
        for x in range(0, no_chains):
            if success.value > 0:
                return (
                    False,
                    false_alarms,
                    gen_hashes,
                    false_alarm_hashes,
                    success_hashes,
                    password_guess
                    
                )
            current_end_point = end_points[table_id][x]
            if current_end_point == hash_of_password:
                password_guess = find_chain_entry(
                    table_id=table_id,
                    chain_number=x,
                    stop_point=((chain_length - NUM_HASHES) - i),
                    start_points=start_points,
                    input_size=input_size,
                )
                temp_hash_count = (chain_length- NUM_HASHES) - i

                # checks if we got original preimage
                if password_guess == true_password:
                    success_hashes = temp_hash_count
                    success.value += 1
                    return (
                        True,
                        false_alarms,
                        gen_hashes,
                        false_alarm_hashes,
                        success_hashes,
                        password_guess,
                    )

                # checks if we got colliding preiamge
                fully_hashed_password_guess = password_guess
                for temp in range(NUM_HASHES):
                    fully_hashed_password_guess = apply_hash(
                        fully_hashed_password_guess, input_size
                    )
                if fully_hashed_password_guess == y:
                    success_hashes = temp_hash_count
                    success.Value += 1
                    return (
                        True,
                        false_alarms,
                        gen_hashes,
                        false_alarm_hashes,
                        success_hashes,
                        password_guess,
                    )

                else:
                    was_reduced, reduced_val = would_be_reduced(
                        password_guess, input_size, NUM_HASHES
                    )
                    if was_reduced:
                        print(
                            bytes_to_string(password_guess)
                            + " reduced to "
                            + bytes_to_string(reduced_val)
                            + " and couldn't be reversed!"
                            + " True password is "
                            + bytes_to_string(tp)
                        )
                    false_alarm_hashes += temp_hash_count
                    false_alarms += 1

        # go to next hash
        if is_dp(hash_of_password, input_size):
            hash_of_password = apply_reduction(
                table_id, hash_of_password, input_size
            )
        else:
            hash_of_password = apply_hash(hash_of_password, input_size)
            gen_hashes = gen_hashes + 1

    return (
        False,
        false_alarms,
        gen_hashes,
        false_alarm_hashes,
        success_hashes,
        b"",  # this will be ignored
    )