#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'aescbc'
require 'openssl'


TEST = "alert('MZA who was that?');\n"
HACK = "alert('Ayo, the Wu is back!');\n"

def mactest
    #key, iv and solution from the challenge
    key = "YELLOW SUBMARINE"
    iv =  "\x00" * 16

    aes = AESCBC.new(iv, key)
    padded = aes.add_pad(TEST)
    encrypted = aes.encrypt_cbc(padded)
    mac = aes.get_mac(encrypted)
    raise "MAC broken" unless  mac == "296b8d7cb78a243dda4d0a61d33bbdd1"
    puts "AES-MAC tested"
    return mac

end



#Test harness
goalmac = mactest
puts "HASH for legit string: " + goalmac
#Convert to binary
bingoalmac = goalmac.scan(/../).map { |x| x.hex.chr }.join

#Generate the MAC for the target string
key = "YELLOW SUBMARINE"
iv =  "\x00" * 16
aes = AESCBC.new(iv, key)
mac = aes.add_pad(HACK)
mac = aes.encrypt_cbc(mac)
mac = aes.get_mac(mac)

puts "Generated hash for forged string: " + mac
#Convert to binary
forgedmac = mac.scan(/../).map { |x| x.hex.chr }.join

#Decrypt the goalmac for last state

cipher = OpenSSL::Cipher.new('AES-128-ECB')
cipher.decrypt
cipher.padding = 0 #Note: OpenSSL will try to pad
                   #even a single ECB Block otherwise
cipher.key = key
laststate = cipher.update(bingoalmac) + cipher.final

addmac = aes.block_xor(forgedmac, laststate)

#Based on this attack, HACK + addmac should generate collision
mac2 = aes.add_pad(HACK)
mac2 = aes.encrypt_cbc(mac2 + addmac)
mac2 = aes.get_mac(mac2)

puts "HASH for string: #{aes.add_pad(HACK)} is: " + mac2

