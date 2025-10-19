from bcrypt import hashpw
from nltk.corpus import words
from time import perf_counter
from multiprocessing import Pool, cpu_count
from math import ceil

database = [word for word in words.words() if 6 <= len(word) <= 10]
shadow = [
"Bilbo: $2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq",
"Gandalf: $2b$08$J9FW66ZdPI2nrIMcOxFYI.q2PW6mqALUl2/uFvV9OFNPmHGNPa6YC",
"Thorin: $2b$08$J9FW66ZdPI2nrIMcOxFYI.6B7jUcPdnqJz4tIUwKBu8lNMs5NdT9q",
"Fili: $2b$09$M9xNRFBDn0pUkPKIVCSBzuwNDDNTMWlvn7lezPr8IwVUsJbys3YZm",
"Kili: $2b$09$M9xNRFBDn0pUkPKIVCSBzuPD2bsU1q8yZPlgSdQXIBILSMCbdE4Im",
"Balin: $2b$10$xGKjb94iwmlth954hEaw3O3YmtDO/mEFLIO0a0xLK1vL79LA73Gom",
"Dwalin: $2b$10$xGKjb94iwmlth954hEaw3OFxNMF64erUqDNj6TMMKVDcsETsKK5be",
"Oin: $2b$10$xGKjb94iwmlth954hEaw3OcXR2H2PRHCgo98mjS11UIrVZLKxyABK",
"Gloin: $2b$11$/8UByex2ktrWATZOBLZ0DuAXTQl4mWX1hfSjliCvFfGH7w1tX5/3q",
"Dori: $2b$11$/8UByex2ktrWATZOBLZ0Dub5AmZeqtn7kv/3NCWBrDaRCFahGYyiq",
"Nori: $2b$11$/8UByex2ktrWATZOBLZ0DuER3Ee1GdP6f30TVIXoEhvhQDwghaU12",
"Ori: $2b$12$rMeWZtAVcGHLEiDNeKCz8OiERmh0dh8AiNcf7ON3O3P0GWTABKh0O",
"Bifur: $2b$12$rMeWZtAVcGHLEiDNeKCz8OMoFL0k33O8Lcq33f6AznAZ/cL1LAOyK",
"Bofur: $2b$12$rMeWZtAVcGHLEiDNeKCz8Ose2KNe821.l2h5eLffzWoP01DlQb72O",
"Durin: $2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay"]


def chunked(lst, n_chunks):
    L = len(lst)
    if n_chunks <= 0:
        return []
    chunk_size = ceil(L / n_chunks)
    return [lst[i*chunk_size : (i+1)*chunk_size] for i in range(n_chunks)]

def brute_force(username, salt, password, chunk):
    start = perf_counter()
    for phrase in chunk:
        attempt = hashpw(bytes(phrase, "utf-8"), salt)
        if (attempt == password):
            end = perf_counter()
            print(f"Password found! {username}'s password is '{phrase}'.\nTime Elapsed to crack the password was {end-start} seconds")
            return

def wrapper(args_tuple):
    username, salt, password, chunk = args_tuple
    return brute_force(username, salt, password, chunk)

def main():
    processes = cpu_count()-1
    chunks = chunked(database, processes) 

    for user in shadow:
        #Gets everything before the space
        user = user.split()
        username = user[0][:-1]
        salt = bytes(user[1][:29],"utf-8")
        password = bytes(user[1],"utf-8")
        
        args = [(username, salt, password, c) for c in chunks]

        print(f"Attempting to break {username}'s password\n")

        with Pool(processes) as pool:
            for result in pool.imap_unordered(wrapper, args):
                if result is not None:
                    pool.terminate()
                    pool.join()
                    break
            


if __name__ == "__main__":
    main()