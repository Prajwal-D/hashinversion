# Imports
import random
import hashlib as h
import time
import numpy as np

hash_data_type = np.dtype('S4')
num_bytes = 4
zeros = 0

"""Write the generated results to a .txt file"""

def writeResults(p):
  f = open("DPData.txt", "a")
  for i in range(0, 15):
    f.write(str(p[i]) + "--")
  f.write('\n')
  f.close()


"""f_i(x) = g_i(h(x)) - apply hash function then reduction function (XOR with i)"""

def apply_function(i, current):
  current = h.sha1(current).digest()[:num_bytes]
  current = bytes(x^y for x, y in zip(i, current))[:num_bytes]
  return current


"""Generate random password of a given size"""

def get_random_password(size):
  new = random.getrandbits(size)
  password = new.to_bytes(num_bytes, "big")
  hashed_value = apply_function(zeros, password)
  return (password, hashed_value)


"""Generate a list of random hashes to attempt to invert"""

def generate_passwords(num, num_bits):
  my_passwords = list()
  for i in range(num):
    my_passwords.append(get_random_password(num_bits))
  return my_passwords


"""Check if the value passed meets the condition passed (n 0s at the start)"""
def meet_condition(value, num_bits):

    zeros = 0
    value = int.from_bytes(value)
    binary_zeros = f'{zeros:08b}'
    binary_value = f'{value:08b}'

    #append correct amount of preceeding zeros for the comparison
    while(len(binary_value) < num_bytes * 8):
        binary_value = '0'+ binary_value

    return (binary_value[:num_bits] == binary_zeros[:num_bits])

"""Generate a single random start point and returns it"""

def get_start_point(input_size):
    new = random.getrandbits(input_size)
    sp = new.to_bytes(num_bytes, "big")
    return sp

"""Repeatedly call the get_start_point function in order to generate all requiered start points"""

def gen_start_points(num_tables, num_chains, input_size):
    global num_bytes
    num_bytes = input_size//8

    start_points = [[0 for i in range(num_chains)] for j in range(num_tables)]
    start_points = np.array(start_points, dtype=hash_data_type)

    for i in range(0, num_tables):
        for j in range(0, num_chains):
            start_points[i,j] = get_start_point(input_size)
    
    return start_points


"""Calculate the end point for a given start point, or recalulcate and replace the start point if the
start point does not lead to a valid end point"""

def get_end_point(start_point, table_num, max_length, condition, input_size):
    completed = False
    while(not completed):
        current = start_point
        count = 0
        while(not meet_condition(current, condition) and count < max_length):
            current = apply_function(table_num.to_bytes(num_bytes, "big"), current)
            count += 1
            
        if(count >= max_length or count == 0):
            start_point = get_start_point(input_size)
        
        else:
            completed = True # can probably delete
            return start_point, current, count
        

"""Remove duplicate end points and regenerate the chains for the shorter duplicates"""

def find_duplicates(end_points, chain_lengths):
    previous = end_points[0]
    duplicate_indices = list()
    for i in range(0, len(end_points)-1):
        if(previous == end_points[i+1]):
            if(chain_lengths[i] >= chain_lengths[i+1]):
              duplicate_indices.append(i+1)
            else:
              duplicate_indices.append(i)
        previous = end_points[i]
    return duplicate_indices


def gen_end_points(start_points, condition, max_length, input_size):
    global num_bytes
    duplicates_exist = True
    num_chains = len(start_points[0])
    num_tables = len(start_points)

    end_points = [[0 for i in range(num_chains)] for j in range(num_tables)]
    end_points = np.array(end_points, dtype=hash_data_type)

    chain_lengths = [[0 for i in range(num_chains)] for j in range(num_tables)]
    chain_lengths = np.array(chain_lengths, dtype='i4')
            
    for i in range(0, num_tables):
        for j in range(0, num_chains):
            start_points[i,j], end_points[i,j], chain_lengths[i,j] = get_end_point(start_points[i,j], i, max_length, condition, input_size)
    
    while(duplicates_exist):
        duplicates_exist = False
        
        #sort start and end points
        replace = list()
        for i in range(0, num_tables):
            order = np.argsort(end_points[i])
            start_points[i] = start_points[i][order]
            end_points[i] = end_points[i][order]
            chain_lengths[i] = chain_lengths[i][order]
            replace.append(find_duplicates(end_points[i], chain_lengths[i]))

        for i in range(0, num_tables):
            for chain in replace[i]:
                if(len(replace[i]) != 0):
                    duplicates_exist = True
                start_points[i,chain] = get_start_point(input_size)
                start_points[i,chain], end_points[i,chain], chain_lengths[i,chain] = get_end_point(start_points[i,chain], i, max_length, condition, input_size)

    return start_points, end_points, chain_lengths

"""Method to recalculate chain up to a specified stop point"""

def find_chain_entry_dp(chain_number, stop_point, start_points, table_number):
    current = start_points[table_number, chain_number]
    c = table_number.to_bytes(num_bytes, "big")
    for i in range(0, stop_point):
      current = apply_function(c, current)
    return current


"""Method to search through the chains of the Hellman table and attempt to
inverse a specific value. Returns true if it is able to do so and false
if it is unable to do so, alongside the number of false alarms triggered"""

def search_chains_dp(tp, y, start_points, end_points, chain_lengths, condition):

  true_password = tp
  hash_of_password = y
  num_tables = len(start_points)
  num_chains = len(start_points[0])
  false_alarms = 0
  gen_hashes = 0
  false_alarm_hashes = 0
  success_hashes = 0

  for x in range(0, num_tables):

    hash_of_password = y

    c = x.to_bytes(num_bytes, "big")

    #applying XOR
    hash_of_password = bytes(a^b for a, b in zip(c, hash_of_password))[:num_bytes]

    #get maximum chain length per table
    max_chain = np.max(chain_lengths[x])

    #perform hash if no matching end point is found up until the length of the chain
    for j in range(0, max_chain):

      #if the current hash value is a distinguished point, i.e., it is in the form of an endpoint
      if(meet_condition(hash_of_password, condition)):

        #check each chains endpoints
        for i in range (0, num_chains):

          current_end_point = end_points[x,i]

          if (current_end_point == hash_of_password and chain_lengths[x,i] < max_chain):

            #the password / input is the previous member of the chain, so recompute from corresponding start point
            password_guess = find_chain_entry_dp(chain_number=i, stop_point=chain_lengths[x,i]-j-1, start_points=start_points, table_number=x)
            temp_hash_count = chain_lengths[x,i]-j-1

            if(password_guess == true_password):
              success_hashes = temp_hash_count
              return (True, false_alarms, gen_hashes, false_alarm_hashes, success_hashes)

            else:
              false_alarm_hashes += temp_hash_count
              false_alarms = false_alarms + 1

      hash_of_password = apply_function(c, hash_of_password)
      gen_hashes += 1

  #no match is found after everything is complete
  return (False, false_alarms, gen_hashes, false_alarm_hashes, success_hashes)


def hellman_table_dp(no_tables, no_chains, no_iterations, condition, max_length, hash_size):

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
  data_type_string = ('S' + str(num_bytes))
  hash_data_type = np.dtype(data_type_string)

  #time the Hellman table creation
  start = time.time()
  my_start_points = gen_start_points(no_tables, no_chains, hash_size)
  my_data = gen_end_points(my_start_points, condition, max_length, hash_size)
  my_start_points = my_data[0]
  my_end_points = my_data[1]
  chain_lengths = my_data[2]
  end = time.time()
  table_time = end-start

  my_passwords = generate_passwords(no_iterations, hash_size)

  #time search algorithm
  start = time.time()
  for i in range(no_iterations):
    x = search_chains_dp(my_passwords[i][0], my_passwords[i][1], my_start_points, my_end_points, chain_lengths, condition)
    false_alarms += x[1]
    if(x[0]):
      inverse_success += 1
    gen_hashes += x[2]
    false_alarm_hashes += x[3]
    success_hashes += x[4]

  end = time.time()
  search_time = end-start

  accuracy = inverse_success / no_iterations
  average_len = np.average(chain_lengths)

  return (accuracy, false_alarms, average_len, table_time, search_time, gen_hashes, false_alarm_hashes, success_hashes)


def masterMethod(p):
  parameters = p
  start = time.time()
  my_results = hellman_table_dp(no_tables=parameters[0], no_chains=parameters[1], no_iterations=parameters[2], condition=parameters[3], max_length=parameters[4], hash_size=parameters[5])
  end = time.time()

  #accuracy
  parameters.append(my_results[0]*100)

  #append the number of false alarms
  parameters.append(my_results[1])

  #append the average length of the chains
  parameters.append(my_results[2])

    #general hashes
  parameters.append(my_results[5])

  #false alarm hashes
  parameters.append(my_results[6])

  #success hashes
  parameters.append(my_results[7])

  #append time taken for chain generation algorithm
  parameters.append(my_results[3])

  #append time taken for search algorithm
  parameters.append(my_results[4])

  #append total execution time
  total_time = end-start
  parameters.append(total_time)

  #write results to file
  writeResults(parameters)


parameters = [100, 100, 100, 8, 1000, 32]
masterMethod(parameters)