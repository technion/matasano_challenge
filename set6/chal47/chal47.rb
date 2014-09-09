#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'rsa'

TEST = "Implying" 
SECRET = "kick it, CC"

def rsatest
    r = RSA.new

    #Testing functions that add padding
    padded = r.encrypt_add_pad(TEST)
    plain = r.encrypt_remove_pad(padded)
    raise "Padding failed" unless plain == TEST

    #Test string to octet functions
    i = r.os2ip(padded)
    s = r.i2osp(i)
    raise "String octet conversion failed" unless s == padded

    #Test the encrypt/decrypt process
    c = r.encrypt(i)
    d = r.decrypt(c)
    raise "Encryption cycle failed" unless i == d

    #Complete the decryption process
    i = r.i2osp(d.to_i)
    plain = r.encrypt_remove_pad(i)
    raise "Complete process failure" unless plain == TEST
    puts "RSA encryption successfully tested"
end

def padding_oracle(c)
    #standard decrypt and convert cycle
    plain = $r.decrypt(c)
    plain = $r.i2osp(plain.to_i)

    #This is a naive implementation of the padding removal
    regx =  Regexp.new("\x00\x02", nil, 'n')

    raise "Padding removal failure" unless plain.match(regx)
end

def test_padding_oracle(c)
#Test padding oracle - legit case
    padding_oracle(c)
    broken = c + 5 #Naive guess that this will break the pad
    caught = 0
    begin
        padding_oracle(broken)
    rescue
        caught = 1
    end
    raise "Padding oracle not catching failures" unless caught == 1

    puts "Padding oracle tested"
end

rsatest

$r = RSA.new
e, n = $r.getpubkeys

#Construct an encrypted string
cipher = $r.encrypt_add_pad(SECRET)
cipher = $r.os2ip(cipher)
target = cipher
cipher = $r.encrypt(cipher)

test_padding_oracle(cipher)

#Values used throughout the attack
k = $r.getk
b = 2 ** (8 * (k-2))
#Step 2a: The first 's'
s = n/(3 * b)
found = 0
while found == 0 
    c = $r.encrypt(s)
    test = (cipher * c) % n
    found = 1
    begin
        padding_oracle(test)
    rescue
        found = 0
    end
    s += 1
end
s -= 1 #Remove that extraa addition
puts "Valid s found " + s.to_s

interval = [2 * b, (3 * b) - 1]
#Step 3

#min_r = interval[0] * s - 3 * b + 1
#max_r = interval[1] * s - 2 * b
#aa = (2 * b + max_r * n)/s
#bb = (2 * b - 1 * max_r * n)/s
#interval[0] = [interval[0], aa].max
#interval[1] = [interval[1], bb].min
#puts interval[0]
#puts interval[1]

#exit
#Step 2c: searching

while 1
    r = 2 * ((interval[1] * s) - 2 * b) / n
    s = (2 * b + r * n) / interval[1]
    found = 0
    while 1
        c = $r.encrypt(s)
        test = (cipher * c) % n
        found = 1
        begin
            padding_oracle(test)
        rescue
            found = 0
        end
        break if found == 1
        
        s += 1
        if s > ( (3 * b + r * n) / interval[0] )
            puts "Limit exceeded, incrementing r"
            r += 1
            s = (2 * b + r * n) / interval[1]
        end

    end
    puts "Sound found was " + s.to_s

    first = [interval[0], (2 * b + r * n)/s].max
    second = [interval[1], (3 * b - 1 + r * n)/s].min

    puts first
    puts second
    break if first == second
    s += 1
end

puts "Your target is: " + target.to_s
puts "Got " + first.to_s



