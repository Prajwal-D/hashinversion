# Imports
import random
import hashlib as h
import time
import numpy as np

hash_data_type = np.dtype('S4')
num_bytes = 4
# random.seed("testSeed")

"""f_i(x) = g_i(h(x)) - apply hash function then reduction function (XOR with i)"""

def apply_function(i, current):
  current = h.sha1(current).digest()[:num_bytes]
  current = bytes(x^y for x, y in zip(i, current))[:num_bytes]
  return current


"""Generate random password of a given size"""

def get_random_password(size):
  global num_bytes

  num_bytes = size // 8
  new = random.getrandbits(size)
  password = new.to_bytes(num_bytes, "big")
  hashed_value = apply_function(b'\x00\x00\x00\x00', password)
  return (password, hashed_value)


"""Generate a list of random hashes to attempt to invert"""

def generate_passwords(num, num_bits):
  my_passwords = list()
  for i in range(num):
    my_passwords.append(get_random_password(num_bits))
  # my_passwords[0] = (b'\x1f\xb0\xb4\xec', h.sha1(b'\x1f\xb0\xb4\xec').digest()[:4])
  # my_passwords[1] = (b'\xcf.\xfd\x1f', h.sha1(b'\xcf.\xfd\x1f').digest()[:4])
  # # print(my_passwords[0])
  # print(my_passwords[1])
  return my_passwords


"""Generate a single random start point, returns the start point alongside empty values for end point and chain
length in the form of a 3 element triple to be stored in the Hellman Table """

def get_start_point(input_size):
    new = random.getrandbits(input_size)
    # num_bytes = input_size//8
    sp = new.to_bytes(num_bytes, "big")
    return sp


"""Repeatedly call the gen_start_point function in order to generate all requiered start points"""

def gen_start_points(num_chains, input_size):
    global num_bytes
    num_bytes = input_size//8
    start_points = [0 for i in range(num_chains)]
    start_points = np.array(start_points, dtype=hash_data_type)

    for i in range(0, num_chains):
        start_points[i] = get_start_point(input_size)
    
    return start_points


"""Calculate the end point for a given start point, or recalulcate and replace the start point if the
start point does not lead to a valid end point"""     

def get_end_point(start_point, chain_length):
    current = start_point
    # print(start_point)
    for i in range(0, chain_length):
        current = apply_function(i.to_bytes(num_bytes, "big"), current)
        # print(current)
    # print("")
    return current


"""Remove duplicate end points and regenerate the chains for the shorter duplicates"""

def remove_duplicates(start_points, end_points):
    previous = end_points[0]
    duplicate_indices = list()
    for i in range(0, len(end_points)-1):
        if(previous == end_points[i+1]):
            # print("Duplicates!", previous, "and", end_points[i], " at indexes", i, "and", i+1)
            duplicate_indices.append(i+1)
        previous = end_points[i]
    return start_points, end_points, duplicate_indices


"""Generate the specified number of end points and also removes duplicate rows."""

def gen_end_points(start_points, chain_length, input_size):
    global num_bytes
    duplicates_exist = True
    num_chains = len(start_points)

    end_points = [0 for i in range(num_chains)]
    end_points = np.array(end_points, dtype=hash_data_type)
        
    for i in range(0, num_chains):
        end_points[i] = get_end_point(start_points[i], chain_length)
    
    # print(start_points)
    # print(end_points)
    while(duplicates_exist):
        # print("Checking for duplicates")
        order = np.argsort(end_points)

        #sort start and end points
        start_points = start_points[order]
        end_points = end_points[order]
        # print(order)
        # print(start_points)
        # print(end_points)
        start_points, end_points, replace = remove_duplicates(start_points, end_points)

        # print(replace)

        if(len(replace) != 0):
            for chain in replace:
                start_points[chain] = get_start_point(input_size)
                end_points[chain] = get_end_point(start_points[chain], chain_length)
                # print("Replaced chain", chain)
        else:
           duplicates_exist = False

    return start_points, end_points


"""Method to recalculate chain up to a specified stop point"""

def find_chain_entry(chain_number, stop_point, start_points):
  current = start_points[chain_number]
  for i in range(stop_point):
    current = apply_function(i.to_bytes(num_bytes, "big"), current)
  return current

"""Method to search through the chains of the rainbow table, returns true or false and
the number of collisions / false alarms that occurred"""
def search_chains(tp, y, start_points, end_points, chain_length):

  true_password = tp
  num_chains = len(start_points)
  false_alarms = 0

  # y
  hash_of_password = y

  #1
  for i in range(chain_length, 0, -1):

    hash_of_password = y

    #g_i(y)
    # if(i == chain_length):
    hash_of_password = bytes(x^y for x, y in zip((i-1).to_bytes(num_bytes, "big"), hash_of_password))[:num_bytes]

    for j in range(i, chain_length):
      # hash_of_password = bytes(x^y for x, y in zip(i.to_bytes(num_bytes, "big"), hash_of_password))[:num_bytes]
      hash_of_password = apply_function((j).to_bytes(num_bytes, "big"), hash_of_password)

    for x in range(0, num_chains):
      current_end_point = end_points[x]
      if(current_end_point == hash_of_password):
        # print("Match found in chain", x, "after", (chain_length-i+1), "iterations")
        password_guess = find_chain_entry(chain_number=x, stop_point=i-1, start_points=start_points)
        # print(password_guess)

        if(password_guess == true_password):
          # print("Success!")
          # print("Inverted", y, "into", password_guess, "after match found with", current_end_point)
          return (True, false_alarms)
        
        else:
          # print("False alarm")
          false_alarms += 1
  
  # print("Failure to invert", y, "should be finding", tp)
  return (False, false_alarms)


"""Write the generated results to a .txt file"""

def writeResults(p):
  # f = open("HellmanNumPy.txt", "a")
  for i in range(0, 9):
    # f.write(str(p[i]) + "--")
    print(str(p[i]) + "--")
  # f.write('\n')
  # f.close()


"""Rainbow table class"""

def rainbow_table(no_chains, chain_len, no_iterations, hash_size):

  collision_count = 0
  inverse_success = 0

  #time Hellman table creation
  start = time.time()
  my_start_points = gen_start_points(no_chains, hash_size)
  my_start_points, my_end_points = gen_end_points(my_start_points, chain_len, hash_size)
  # print(my_start_points[0])
  # print(my_start_points[1])
  end = time.time()
  table_time = end-start

  my_passwords = generate_passwords(no_iterations, hash_size)

  #time search algorithm
  start = time.time()
  for i in range(no_iterations):
    x = search_chains(my_passwords[i][0], my_passwords[i][1], my_start_points, my_end_points, chain_len)
    collision_count += x[1]
    if(x[0]):
      inverse_success += 1

  end = time.time()
  search_time = end-start

  accuracy = inverse_success / no_iterations
  return (accuracy, collision_count, table_time, search_time)


"""Master method which calls rainbow table and write results as well as times the
length of execution"""

def masterMethod(p):
  # global my_set
  # my_set = set()
  parameters = p
  start = time.time()
  my_results = rainbow_table(no_chains=parameters[0], chain_len=parameters[1], no_iterations=parameters[2], hash_size=parameters[3])
  end = time.time()

  #accuracy
  parameters.append(my_results[0]*100)

  #collision_count
  parameters.append(my_results[1])

  #table generation time
  parameters.append(my_results[2])

  #search algorithm time
  parameters.append(my_results[3])

  #total execution time
  total_time = end-start
  parameters.append(total_time)

  #total unique values in table
  # coverage = len(my_set)
  # parameters.append(coverage)

  #number of searched values within the set of unique values in table
  # parameters.append(my_results[4])

  #write file
  writeResults(parameters)


parameters = [1500, 1500, 100, 32]
masterMethod(parameters)

# my_sp = gen_start_points(100, 32)
# my_ep = gen_end_points(my_sp, 5, 32)