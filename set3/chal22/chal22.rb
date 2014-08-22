#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'MT19937'

Forcelevel = 300 #How many seconds to try and backtrack

#Create a seeded generator and get first output
t = Time.new
puts "Seed value was #{t.strftime("%s")}"
r = MT19937.new(t.strftime("%s").to_i)
target = r.extract_numbers

#Sleeping a while
delay = rand(20)
puts "Sleeping #{delay} seconds"
sleep(delay)

(0..Forcelevel).each { |n|
    #Brute force the ssed by backtracking from current time
    t = Time.new
    t -= n
    r = MT19937.new(t.strftime("%s").to_i)

    if r.extract_numbers == target
        puts "The seed was brute forced to #{t.strftime("%s")}"
        break
    end
    if n == Forcelevel
        raise "Seed not located"
    end
}

