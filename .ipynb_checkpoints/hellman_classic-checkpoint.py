#imports
import random
import hashlib as h
import time
import numpy as np

hash_data_type = np.dtype('S4')
num_bytes = 4
zeros = 0

"""Write the generated results to a .txt file"""

def writeResults(p):
  f = open("HellmanData.txt", "a")
  for i in range(0, 13):
    f.write(str(p[i]) + "--")
  f.write('\n')
  f.close()

"""Apply function - hash and then XOR."""

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

"""Calculate the end point for a given start point in a given table"""

def get_end_point(start_point, table_num, chain_length):
  current = start_point
  for i in range(0, chain_length):
    current = apply_function(table_num.to_bytes(num_bytes, "big"), current)
  return current

"""Generate end point method"""

def gen_end_points(start_points, chain_length):

  num_tables = len(start_points)
  num_chains = len(start_points[0])

  end_points = [[0 for i in range(num_chains)] for j in range(num_tables)]
  end_points = np.array(end_points, dtype=hash_data_type)

  #iterate through tables
  for c in range(0, num_tables):
    #itereate through start points
    for i in range(0, num_chains):
      end_points[c,i] = get_end_point(start_points[c,i], c, chain_length)

  return end_points

"""Method to recalculate chain up to a specified stop point"""

def find_chain_entry(chain_number, stop_point, start_points, table_number):
  current = start_points[table_number, chain_number]
  c = table_number.to_bytes(num_bytes, "big")
  for i in range(0, stop_point):
    current = apply_function(c, current)
  return current

"""Inverse hash method"""

def search_chains(tp, y, start_points, end_points, chain_length):

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

    c = x.to_bytes(4, "big")

    #applying XOR
    hash_of_password = bytes(a^b for a, b in zip(c, hash_of_password))[:4]

    # generate list
    chain_for_y = list()
    chain_for_y.append(hash_of_password)
    hash_copy = hash_of_password

    for z in range(0, chain_length):
      hash_copy = apply_function(c, hash_copy)
      chain_for_y.append(hash_copy)

    #perform hash if no matching end point is found up until the length of the chain
    for j in range(0, chain_length):
      #check each chains endpoints
      for i in range (0, num_chains):

        current_end_point = end_points[x,i]

        if (current_end_point == hash_of_password) and (chain_for_y.count(current_end_point) != 0):
        # if (current_end_point == hash_of_password):

          #the password / input is the previous member of the chain, so recompute from corresponding start point
          password_guess = find_chain_entry(chain_number=i, stop_point=chain_length-j-1, start_points=start_points, table_number=x)
          temp_hash_count = chain_length-j-1

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

"""Generate a given number of password and hash pairs and return them"""

def generate_passwords(num, num_bits):
  my_passwords = list()
  for i in range(num):
    my_passwords.append(get_random_password(num_bits))
  return my_passwords

"""Full Hellman table method"""

def hellman_table(no_tables, no_chains, chain_len, no_iterations, hash_size):

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

  #time Hellman table creation
  start = time.time()
  my_start_points = gen_start_points(no_tables, no_chains, hash_size)
  my_end_points = gen_end_points(my_start_points, chain_len)
  end = time.time()
  table_time = end-start

  my_passwords = generate_passwords(no_iterations, hash_size)

  #time search algorithm
  start = time.time()
  for i in range(no_iterations):
    x = search_chains(my_passwords[i][0], my_passwords[i][1], my_start_points, my_end_points, chain_len)
    false_alarms += x[1]
    if(x[0]):
      inverse_success += 1
    gen_hashes += x[2]
    false_alarm_hashes += x[3]
    success_hashes += x[4]

  end = time.time()
  search_time = end-start

  accuracy = inverse_success / no_iterations

  return (accuracy, false_alarms, table_time, search_time, gen_hashes, false_alarm_hashes, success_hashes)

"""Master code"""

"""Format of output is as follows: no_tables,no_chains,chain_length,no_iterations,_hash_size,accuracy(percentage),no_collisions, table generation time,
search algorithm time, total execution time, coverage"""

def masterMethod(p):
  parameters = p
  start = time.time()
  my_results = hellman_table(no_tables=parameters[0], no_chains=parameters[1], chain_len=parameters[2], no_iterations=parameters[3], hash_size=parameters[4])
  end = time.time()

  #accuracy
  parameters.append(my_results[0]*100)

  #false alarms
  parameters.append(my_results[1])

  #general hashes
  parameters.append(my_results[4])

  #false alarm hashes
  parameters.append(my_results[5])

  #success hashes
  parameters.append(my_results[6])

  #table generation time
  parameters.append(my_results[2])

  #search algorithm time
  parameters.append(my_results[3])

  #total execution time
  total_time = end-start
  parameters.append(total_time)

  #write file
  writeResults(parameters)

parameters = [100, 100, 100, 100, 16]
masterMethod(parameters)