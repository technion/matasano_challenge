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
    #Worked backwards to identify
    #http://www.randombit.net/bitbashing/2009/07/21/inverting_mt19937_tempering.html
    y ^= (y >> 18)    
    y ^= (y << 15) & 0xefc60000
    y ^= (y << 7) & 0x1680
    y ^= (y << 7) & 0xc4000
    y ^= (y << 7) & 0xd200000
    y ^= (y << 7) & 0x90000000
    y ^= (y >> 11) & 0xffcc00000
    y ^= (y >> 11) & 0x2ff800
    y ^= (y >> 11) & 0x7ff
    return y
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
