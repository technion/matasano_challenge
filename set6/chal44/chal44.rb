#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl'
require_relative 'dsa'

#Told before hand - this is the hash of the secret we want to crack
xhash = 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'

s1 = 1267396447369736888040262262183731677867615804316
r1 = 1105520928110492191417703162650245113664610474875
m1 = 0xa4db3de27e2db3e5ef085ced2bced91b82e0df19

s2 = 1021643638653719618255840562522049391608552714967 
r2 = 1105520928110492191417703162650245113664610474875 
m2 = 0xd22804c4899b522b23eda34d2137cd8cc22b9ce8 
  
#Create arrays for s, r, m.
#Parse the file for these values
#Sanitise them
file = File.open('44.txt', 'r')
s = []
r = []
m = []

file = File.open('44.txt', 'r')
file.each_line { |line|  
    s.push(line)  if line.match(/s:/)
    r.push(line) if line.match(/r:/)
    m.push(line) if line.match(/m:/)
}

file.close

s = s.map{ |x| x.gsub(/s: /, '').to_i }
r = r.map{ |x| x.gsub(/r: /, '').to_i }
m = m.map{ |x| x.gsub(/m: /, '').to_i(16) }


d = DSA.new
p, q, g = d.getparams

#This loop implements a half assed search. We need to check for a match.
#Here we just check every value against the first. Fortunately that's enough.
(0..10).each { |i|
    # 'k' finder from the challenge
    top = (m[0] - m[i]) % q
    k = top * d.modinv((s[0] - s[i]), q)

    #Function from challenge 43: Get x from candidate k
    top = (s[0] * k) - m1
    bottom = d.modinv(r1, q)
    x = (top * bottom) % q
    hash = d.hashtoint(x.to_s(16))
    if hash.to_s(16) == xhash
        puts "Sucessfully found x: " + x.to_s(16)
        exit
    end
}
raise "Unable to locate x"
