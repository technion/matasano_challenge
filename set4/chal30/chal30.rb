#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'md4'
require_relative 'md4forge'

def keyed_md4(string)
    #Implements a secret key in a SHA
    #Represents the server-side 'security'
    key = "ultrasecretcode"
    string = key + string
    return md4(string)

end

def make_pad(string)
    #Blatantly ripped from md4.rb
    mask = (1 << 32) - 1
    bit_len = string.size << 3
    pad = "\x80"
    while ((string.size + pad.length)% 64) != 56
      pad += "\0"
    end
    pad = pad.force_encoding('ascii-8bit') + [bit_len & mask, bit_len >> 32].pack("V2")

    return pad
end 


Secretpass = 'A' * 15 # Not actually the secret, just a string of same length
text = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
verifier = keyed_md4(text)
puts "Key for basic string"
puts verifier

iv = verifier.scan(/.{8}/)

#Unlike the SHA1 example, there is an endianness issue to resolve
#before injecting the IV. There is supposed to be a Ruby unpack involving
#'V' but I could never get it to work.
iv = iv.map { |x| x.scan(/../).reverse.join.to_i(16) }

#Create our padded string
glue = make_pad(Secretpass + text)
puts "Hacked string:"
puts (Secretpass + text + glue + ";admin=true").inspect

#Testing purposes only - find the real target
puts "Legit key of hacked string"
puts keyed_md4(text + glue + ";admin=true")

puts "Attacked key for hacked string"
#Find the attacked output
puts md4forge(";admin=true", (Secretpass + text + glue).length, iv)


