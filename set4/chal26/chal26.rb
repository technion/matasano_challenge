#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl'
require_relative 'aesctr'

def gen_cookie(str)
    #Generates a string matching specification
    #Adds PKCS#7 padding and encrypts it
    str = str.gsub(/[;=]/, '!')
    str = "comment1=cooking%20MCs;userdata="  + str
    str = str + ";comment2=%20like%20a%20pound%20of%20bacon"
    cipher = AESCTR.new
    return cipher.endecrypt(str)
end

def check_cookie(str)
    cipher = AESCTR.new
    str = cipher.endecrypt(str)
    if str.match(/admin=true/)
        return true
    else
        return false
    end
end

safe = gen_cookie("My voice is my password adminAtrue verify me")

#This is the byte in the prior to block to the target character
offset = "comment1=cooking%20MCs;userdata=".length
offset += "My voice is my password admin".length

#XOR the ciphertext against our holding character against the target
safe[offset] = ((safe[offset]).ord ^ 'A'.ord ^ '='.ord).chr
ret = check_cookie(safe)

puts "Calling check cookie, does it believe are admins?"
puts ret

exit

#Debugging
#padstr = add_pad("YELLOW SUBMARINEYELLOW SUBMARI")
#str = encrypt_cbc(padstr)
#back = decrypt_cbc(str)
#back = remove_pad(back)
#puts back
#puts back.unpack('H*').join
