#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'MT19937'
class MT19937clone < MT19937
    def setstate(state)
       raise "Invalid state type" unless state.kind_of? Array

       @mt = state
       @index = 0

    end
end

Statesize = 624

def temper(y)
    #The temper function from MT, here to test against
    y ^= (y >> 11)
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= (y >> 18)
    
    return y
end

def untemper(y)
    #Port of https://github.com/gaganpreet/matasano-crypto-3/blob/ab1f8684d3730eb67029e0d6c9e53113a2dedcee/src/clone_mt.py
    y = y ^ (y >> 18)
    y = y ^ ((y << 15) & 4022730752)
    y = untemper2(y)
    y = untemper3(y)
    return y
end
def untemper3(y)
    a = y >> 11
    b = y ^ a
    c = b >> 11
    return (y ^ c)
end

def untemper2(y)
    mask = 2636928640
    a = y << 7
    b = y ^ (a & mask)
    c = b << 7
    d = y ^ (c & mask)
    e = d << 7
    f = y ^ (e & mask)
    g = f << 7
    h = y ^ (g & mask)
    i = h << 7
    k = y ^ (i & mask)
    return k
end


[10, 1337, 34324].each { |n|
    t = temper(n)
    u = untemper(t)
    raise "Untemper failer on #{n}" unless n == u
}

puts "Sucessfully verified untemperer"

#Create a seeded generator and get first output
t = Time.new
puts "Seed value was #{t.strftime("%s")}"
#r = MT19937.new(t.strftime("%s").to_i)
r = MT19937.new(45)

mtstate = []
(0..Statesize-1).each { |n|
    target = r.extract_numbers
    mtstate[n] = untemper(target)
}

clone = MT19937clone.new(0)
clone.setstate(mtstate)

10.times{ 
    puts "Next random was #{r.extract_numbers}"
    puts "Next clone random was #{clone.extract_numbers}"
}
