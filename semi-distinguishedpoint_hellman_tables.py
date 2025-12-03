#!/usr/bin/env python
# coding: utf-8

# Notes to self:
# 
# Need to fix the global variables to never mutate, probably replace them, confusing as hell
# 
# DO NOT CHANGE NUM_BYTES from 4 or there will be dragons!!! I really don't know why it is working as it is, especially since it should be 2!!!
# 
# amount of hashes hardcoded = 2
# 
# dpt significance = ends with 8 zeros

# In[1]:


import black
import jupyter_black

jupyter_black.load(
    line_length=79,
    verbosity="DEBUG",
    target_version=black.TargetVersion.PY310,
)


# In[2]:


import random
import hashlib as h
import time
import numpy as np

NUM_HASHES = 10

hash_data_type = np.dtype("S4")
num_bytes = 4
zeros = 0
list_of_password_extractions = []
list_of_colliding_hashes = []


# In[3]:


"""Helper function to visualise passwords as hex strings"""


def bytes_to_string(bytes_data):
    intRepresentation = int.from_bytes(bytes_data, "big")
    return "0x{0:x}".format(intRepresentation)


# In[4]:


"""Write the generated results to a .txt file"""


def writeResults(p):
    f = open("SDPTemp.txt", "a")
    for i in range(0, 13):
        f.write(str(p[i]) + "--")
    f.write("\n")
    f.close()


# In[5]:


"""h(x) - apply only hash function"""


def apply_hash(current):
    global num_bytes

    current = h.sha1(current).digest()[:num_bytes]
    return current


# In[6]:


"""f_i(x) = g_i(h(x)) - apply reduction function unique to table (XOR with table num)
this currently works because last bits are checked for dpt, not first
"""


def apply_reduction(table_id, current):
    global num_bytes

    table_id = table_id + 1  # makes sure table_id is not 0
    table_id_bytes = table_id.to_bytes(num_bytes, "big")
    current = bytes(x ^ y for x, y in zip(table_id_bytes, current))[:num_bytes]
    return current


# In[7]:


table_id = 1
table_id_bytes = table_id.to_bytes(2, "big")
print(table_id_bytes)
print(table_id_bytes[::-1])


# In[8]:


"""Generate random password of a given size, hashed NUM_HASHES times"""


def get_random_password(size):
    global NUM_HASHES

    password_gen_incomplete = True
    while password_gen_incomplete:
        new = random.getrandbits(size)
        password = new.to_bytes(num_bytes, "big")

        hashed_value = password
        for i in range(NUM_HASHES):
            if is_dp(password):
                print("bad pass!")
                # break     # we're gonna allow generating bad passwords
            hashed_value = apply_hash(hashed_value)
            if i == NUM_HASHES - 1:
                password_gen_incomplete = False
        ## if a hashed_value in this loop ends with eight 0s, this password can't be reversed!

    return (password, hashed_value)


# In[9]:


"""Generate a list of random hashes to attempt to invert"""


def generate_passwords(num, num_bits):
    my_passwords = list()
    for i in range(num):
        my_passwords.append(get_random_password(num_bits))
    return my_passwords


# In[10]:


"""Generate a single random start point, returns the start point alongside empty values for end point and chain
length in the form of a 3 element triple to be stored in the Hellman Table"""


def get_start_point(input_size):
    new = random.getrandbits(input_size)
    sp = new.to_bytes(num_bytes, "big")
    return sp


# In[11]:


"""Repeatedly call the get_start_point function in order to generate all requiered start points"""


def gen_start_points(num_chains, input_size):
    global num_bytes
    num_bytes = input_size // 8
    start_points = [0 for i in range(num_chains)]
    start_points = np.array(start_points, dtype=hash_data_type)

    for i in range(0, num_chains):
        start_points[i] = get_start_point(input_size)

    return start_points


# In[12]:


"""Check if a given point is a distinguished point"""


def is_dp(point_in_question):
    global num_bytes

    last_8_bits_mask = b"\xff"
    for i in range(num_bytes - 1):  # last byte is used for dp
        last_8_bits_mask = b"\x00" + last_8_bits_mask

    masked_val = bytes(
        x & y for x, y in zip(last_8_bits_mask, point_in_question)
    )[:num_bytes]
    if int.from_bytes(masked_val, "big") == 0:  ## ends with 8 0s
        return True
    return False


# In[13]:


current = b"\x99\x00"
last_8_bits_mask = bytes(x & y for x, y in zip(b"\x00\xff", current))[
    :num_bytes
]

print(current)
print(last_8_bits_mask)
print(int.from_bytes(last_8_bits_mask, "big"))


# In[14]:


test_bytes = b"\xff"
test_bytes = b"\x00" + test_bytes
test_bytes = b"\x00" + test_bytes

print(test_bytes)


# In[15]:


"""Calculate the end point for a given start point"""


def get_end_point(start_point, chain_length, table_id):
    current = start_point
    for i in range(0, chain_length):
        if is_dp(current):
            current = apply_reduction(table_id, current)
            continue

        current = apply_hash(current)
    return current


# In[16]:


"""Remove duplicate end points and regenerate the chains for the shorter duplicates"""

# NOTE TO SELF: I DON'T THINK WE CAN DO THIS, ASK ABOUT IT


def find_duplicates(end_points):
    previous = end_points[0]
    duplicate_indices = list()
    for i in range(0, len(end_points) - 1):
        if previous == end_points[i + 1]:
            duplicate_indices.append(i + 1)
        previous = end_points[i]
    return duplicate_indices


# In[17]:


"""Generate the specified number of end points and also removes duplicate rows."""


def gen_end_points(start_points, chain_length, input_size, table_id):
    global num_bytes
    duplicates_exist = True
    num_chains = len(start_points)

    end_points = [0 for i in range(num_chains)]
    end_points = np.array(end_points, dtype=hash_data_type)

    for i in range(0, num_chains):
        end_points[i] = get_end_point(start_points[i], chain_length, table_id)

    #     while duplicates_exist:
    #         order = np.argsort(end_points)

    #         # sort start and end points
    #         start_points = start_points[order]
    #         end_points = end_points[order]
    #         replace = find_duplicates(end_points)

    #         if len(replace) != 0:
    #             for chain in replace:
    #                 start_points[chain] = get_start_point(input_size)
    #                 end_points[chain] = get_end_point(
    #                     start_points[chain], chain_length, table_id
    #                 )
    #         else:
    #             duplicates_exist = False

    return start_points, end_points


# In[18]:


"""Method to recalculate chain up to a specified stop point"""


def find_chain_entry(table_id, chain_number, stop_point, start_points):
    current = start_points[table_id][chain_number]
    for i in range(stop_point):
        if is_dp(current):
            current = apply_reduction(table_id, current)
        current = apply_hash(current)
    return current


# In[19]:


def would_be_reduced(password_guess):
    global NUM_HASHES

    for i in range(NUM_HASHES):
        if is_dp(password_guess):
            return True, password_guess
        password_guess = apply_hash(password_guess)

    return False, ""


# In[20]:


"""Method to search through the chains of the dpt tables, returns true or false and
the number of collisions / false alarms that occurred"""


def search_chains(
    tp, y, start_points, end_points, no_tables, no_chains, chain_length
):
    global list_of_password_extractions
    global list_of_colliding_hashes

    global NUM_HASHES

    true_password = tp
    false_alarms = 0
    gen_hashes = 0
    false_alarm_hashes = 0
    success_hashes = 0

    for t in range(no_tables):
        hash_of_password = y  # assume hash is somewhere in a chain

        # the last NUM_HASHES in the chain are irrelevant to us, since we cannot reverse back to them
        for i in range(0, chain_length - NUM_HASHES):
            # search endpoints for hash
            for x in range(0, no_chains):
                current_end_point = end_points[t][x]
                if current_end_point == hash_of_password:
                    password_guess = find_chain_entry(
                        table_id=t,
                        chain_number=x,
                        stop_point=((chain_length - NUM_HASHES) - i),
                        start_points=start_points,
                    )
                    temp_hash_count = chain_length - i

                    # checks if we got original preimage
                    if password_guess == true_password:
                        success_hashes = temp_hash_count
                        list_of_password_extractions.append(
                            [
                                bytes_to_string(tp),
                                bytes_to_string(y),
                                bytes_to_string(password_guess),
                            ]
                        )
                        return (
                            True,
                            false_alarms,
                            gen_hashes,
                            false_alarm_hashes,
                            success_hashes,
                        )

                    # checks if we got colliding preiamge
                    fully_hashed_password_guess = password_guess
                    for temp in range(NUM_HASHES):
                        fully_hashed_password_guess = apply_hash(
                            fully_hashed_password_guess
                        )
                    if fully_hashed_password_guess == y:
                        success_hashes = temp_hash_count
                        list_of_colliding_hashes.append(
                            [
                                bytes_to_string(tp),
                                bytes_to_string(y),
                                bytes_to_string(password_guess),
                            ]
                        )
                        return (
                            True,
                            false_alarms,
                            gen_hashes,
                            false_alarm_hashes,
                            success_hashes,
                        )

                    else:
                        was_reduced, reduced_val = would_be_reduced(
                            password_guess
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
            if is_dp(hash_of_password):
                hash_of_password = apply_reduction(t, hash_of_password)
            else:
                hash_of_password = apply_hash(hash_of_password)
            gen_hashes = gen_hashes + 1

    return (
        False,
        false_alarms,
        gen_hashes,
        false_alarm_hashes,
        success_hashes,
    )


# In[21]:


for i in range(0, 7):
    print(i)


# In[22]:


"""Reduction on Distinguished point with fixed length chains method"""


def fixed_len_dpt(no_tables, no_chains, chain_len, no_iterations, hash_size):

    false_alarms = 0
    inverse_success = 0
    gen_hashes = 0
    false_alarm_hashes = 0
    success_hashes = 0
    global zeros
    global num_bytes
    global hash_data_type

    num_bytes = hash_size // 8
    zeros = 0
    zeros = zeros.to_bytes(num_bytes, "big")
    data_type_string = "S" + str(num_bytes)
    hash_data_type = np.dtype(data_type_string)

    # time sdpt table creation
    start = time.time()

    start_points = [[0 for i in range(no_chains)] for j in range(no_tables)]
    start_points = np.array(start_points, dtype=hash_data_type)
    end_points = [[0 for i in range(no_chains)] for j in range(no_tables)]
    end_points = np.array(end_points, dtype=hash_data_type)

    for table_id in range(no_tables):
        current_start_points = gen_start_points(no_chains, hash_size)
        current_start_points, current_end_points = gen_end_points(
            current_start_points,
            chain_len,
            hash_size,
            table_id,
        )
        start_points[table_id] = current_start_points
        end_points[table_id] = current_end_points

    end = time.time()
    tables_time = end - start

    my_passwords = generate_passwords(no_iterations, hash_size)

    # time search algorithm
    start = time.time()
    for i in range(no_iterations):
        x = search_chains(
            my_passwords[i][0],
            my_passwords[i][1],
            start_points,
            end_points,
            no_tables,
            no_chains,
            chain_len,
        )
        false_alarms += x[1]
        if x[0]:
            inverse_success += 1
        gen_hashes += x[2]
        false_alarm_hashes += x[3]
        success_hashes += x[4]
    end = time.time()
    search_time = end - start

    accuracy = inverse_success / no_iterations
    return (
        accuracy,
        false_alarms,
        tables_time,
        search_time,
        gen_hashes,
        false_alarm_hashes,
        success_hashes,
    )


# In[ ]:


"""Master method which calls rainbow table and write results as well as times the
length of execution"""


def masterMethod(p):
    parameters = p
    start = time.time()
    my_results = fixed_len_dpt(
        no_tables=parameters[0],
        no_chains=parameters[1],
        chain_len=parameters[2],
        no_iterations=parameters[3],
        hash_size=parameters[4],
    )
    end = time.time()

    # accuracy
    parameters.append(my_results[0] * 100)

    # false_alarms
    parameters.append(my_results[1])

    # general hashes
    parameters.append(my_results[4])

    # false alarm hashes
    parameters.append(my_results[5])

    # success hashes
    parameters.append(my_results[6])

    # tables generation time
    parameters.append(my_results[2])

    # search algorithm time
    parameters.append(my_results[3])

    # total execution time
    total_time = end - start
    parameters.append(total_time)

    # write file
    writeResults(parameters)
    print(parameters)


# parameters = [5, 337, 41, 100, 16]
parameters = [255, 10355, 1625, 100, 32]
masterMethod(parameters)


# In[ ]:


list_of_password_extractions


# In[ ]:


list_of_colliding_hashes


# In[ ]:


binary_string = list_of_colliding_hashes[1][1]

