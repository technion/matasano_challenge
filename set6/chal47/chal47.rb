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

def myceil(a, b)
   #This is a utility function.
   res = a / b
   if (a % b)
       res += 1
   end
   return res
end

rsatest

$r = RSA.new
e, n = $r.getpubkeys

#Construct an encrypted string
cipher = $r.encrypt_add_pad(SECRET)
cipher = $r.os2ip(cipher)
target = cipher
cipher = $r.encrypt(cipher)
#Values used throughout the attack
k = $r.getk
puts "k found is " + k.to_s

#This is the "blinding" M assignment
b = 2 ** (8 * (k-2)) #This is "B"
$interval = [2 * b, (3 * b) - 1]
$i = 1

#This is just a test harness. It's called a little late because
#it needs a fully constructed cipher.
test_padding_oracle(cipher)


def step2a(b, n, cipher)
    #Step 2a: The first 's' candidate
    s = n/(3 * b)
    while 1 
        c = $r.encrypt(s)
        test = (cipher * c) % n
        begin
            padding_oracle(test)
            break
        rescue
            s += 1
        end
    end
    return s
end

def step2(s, b, n, cipher)
    if $i == 1
        s = step2a(b, n, cipher)
        puts "Valid s found " + s.to_s
        return s
    end
    s = step2c(s, b, n, cipher)
    return s

end

def step2c(s, b, n, cipher)
    r = myceil(2 * (($interval[1] * s) - 2 * b), n)
    s = (2 * b + r * n) / $interval[1]
    while 1
        c = $r.encrypt(s)
        test = (cipher * c) % n
        begin
            padding_oracle(test)
            break
        rescue
            #Do nothing
        end

        s += 1
        if s > ( (3 * b + r * n) / $interval[0] )
            #puts "Limit exceeded, incrementing r"
            r += 1
            s = (2 * b + r * n) / $interval[1]
        end

    end
    return s

end

def step3(s, b, n)
    min_r = myceil(($interval[0] * s - 3 * b + 1),  n)
    max_r = ($interval[1] * s - 2 * b) / n
    (min_r..max_r).each { |r|
        aa = myceil(2*b + r*n, s)
        bb = (3 * b - 1 + r*n) / s
        $interval[0] = [$interval[0], aa].max
        $interval[1] = [$interval[1], bb].min
    }
    raise "This string had an interval - not implemented" if min_r != max_r
end
    

while($interval[0] != $interval[1])
    s = step2(s, b, n, cipher)
    step3(s, b, n)
    puts "New s value is " + s.to_s
    puts $interval[0]
    puts $interval[1]
    $i += 1
end

#Step 4
#I don't get it - step four never happened and the result still works.
broken = $r.i2osp($interval[0])
broken = $r.encrypt_remove_pad(broken)
puts "Cracked phrase is: " + broken

