#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'sha1'
require_relative 'sha1forge'

def keyed_sha1(string)
    #Implements a secret key in a SHA
    #Represents the server-side 'security'
    key = "ultrasecretcode"
    string = key + string
    return SHA1.hexdigest(string)

end

Secretpass = 'A' * 15 # Not actually the secret, just a string of same length
text = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
verifier = keyed_sha1(text)
puts "Key for basic string"
puts verifier
iv = verifier.scan(/.{8}/)
iv = iv.map { |x| x.to_i(16) }

#Create our padded string
glue = SHA1forge.makeglue(Secretpass + text)
puts "Hacked string:"
puts (text + glue + ";admin=true").inspect

#Testing purposes only - find the real target
puts "Legit key of hacked string"
puts keyed_sha1(text + glue + ";admin=true")

#Find the attacked output
puts SHA1forge.hexdigest(";admin=true", (Secretpass + text + glue).length, iv)


