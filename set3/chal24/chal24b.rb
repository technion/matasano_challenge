#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'MT19937'

def mtkeystream(length,key)
    #Produces a keystream based on MT19937
    raise "Invalid input key" unless key.kind_of? Integer
    raise "Invalid input length" unless length.kind_of? Integer
    gen = MT19937.new(key)
    stream = []
    length.times {
        stream.push(gen.extract_numbers % 256)
    }

    return stream
end

def maketoken
    t = Time.new
    return mtkeystream(16, t.strftime("%s").to_i)
end

tok = maketoken

sleep(5)

#Brute force that token
t = Time.new
(0..5000).each { |n|
    l = t - n
    test = mtkeystream(16, l.strftime("%s").to_i)
    if test == tok
        puts "Cracked generator at #{l.strftime("%s").to_i}"
        break
    end
}
