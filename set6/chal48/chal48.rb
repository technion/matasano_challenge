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

def padding_oracle(c)
    #standard decrypt and convert cycle
    plain = $r.decrypt(c)
    plain = $r.i2osp(plain.to_i)

    #This is a naive implementation of the padding removal
    regx =  Regexp.new("\x00\x02", nil, 'n')

    raise "Padding removal failure" unless plain.match(regx)
end


rsatest

$r = RSA.new
e, n = $r.getpubkeys

#Construct an encrypted string
cipher = $r.encrypt_add_pad(SECRET)
cipher = $r.os2ip(cipher)
cipher = $r.encrypt(cipher)

#Values used throughout the attack
k = $r.getk
puts "k found is " + k.to_s

#This is the "blinding" M assignment
b = 2 ** (8 * (k-2)) #This is "B"
$mininterval = [2 * b]
$maxinterval = [(3 * b) - 1]

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

def step2b(prev_s, b, n, cipher)
    #Step 2b: The next 's' candidate
    s = prev_s + 1
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

def step2c(s, b, n, cipher)
    r = myceil(2 * (($maxinterval[0] * s) - 2 * b), n)
    s = (2 * b + r * n) / $maxinterval[0]
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
        if s > ( (3 * b + r * n) / $mininterval[0] )
            #puts "Limit exceeded, incrementing r"
            r += 1
            s = (2 * b + r * n) / $maxinterval[0]
        end

    end
    return s

end

def step3(s, b, n)
    min_r = myceil(($mininterval[0] * s - 3 * b + 1),  n)
    max_r = ($maxinterval[0] * s - 2 * b) / n
    #return if min_r > max_r

    (min_r..max_r).each { |r|
        aa = myceil(2*b + r*n, s)
        bb = (3 * b - 1 + r*n) / s
        $mininterval[0] = [$mininterval[0], aa].max
        $maxinterval[0] = [$maxinterval[0], bb].min
    }
    if min_r != max_r
        puts "There were #{max_r} #{min_r} top intervals"
    end
end

#It's a lot cleaner if we don't implement 'i'. All it determines is whether
#it's first execution, for step2a vs step2c
s = step2a(b, n, cipher)
puts "Initial s found to be " + s.to_s
step3(s, b, n)    
while 1
    if $mininterval.count == 1
        break if ($mininterval[0] == $maxinterval[0])
        s = step2c(s, b, n, cipher)
    else
        puts "Doing b"
        s = step2b(s, b, n, cipher)
    end
    step3(s, b, n)
    puts "New s value is " + s.to_s
    puts $mininterval[0]
    puts $maxinterval[0]
end

#Step 4
#I don't get it - step four never happened and the result still works.
broken = $r.i2osp($mininterval[0])
broken = $r.encrypt_remove_pad(broken)
puts "Cracked phrase is: " + broken

