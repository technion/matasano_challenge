#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'aescbc'
require 'openssl'


TEST = "Implying this is a test"

def mactest
    key = OpenSSL::Random.random_bytes(16)
    iv = OpenSSL::Random.random_bytes(16)

    aes = AESCBC.new(iv, key)
    padded = aes.add_pad(TEST)
    encrypted = aes.encrypt_cbc(padded)
    decrypted = aes.decrypt_cbc(encrypted)
    plain = aes.remove_pad(decrypted)
    raise "AES-CBC not working" unless plain == TEST
    puts "AES-CBC tested"

    mac = aes.get_mac(encrypted)
    encrypted2 = aes.add_pad(TEST + "broken")
    encrypted2 = aes.encrypt_cbc(encrypted2)
    mac2 = aes.get_mac(encrypted2)
    raise "MAC broken" if mac == mac2
    puts "AES-MAC tested"

end


def randiv
    #Client setup
    key = OpenSSL::Random.random_bytes(16)
    iv = OpenSSL::Random.random_bytes(16)

    aes = AESCBC.new(iv, key)

    #Client gets legit MAC for a transaction to their own account
    s =  "from=50&to=50&amount=100000000"
    mac = aes.add_pad(s)
    mac = aes.encrypt_cbc(mac)
    mac = aes.get_mac(mac)
    puts "Transaction MAC is " + mac


    #Malciously change the 'from' account
    sforged = "from=59&to=50&amount=100000000"
    #Create a forged IV that matches the MAC
    iv[6] = (iv[6].ord ^ s[6].ord ^ '9'.ord).chr
    aes.setiv(iv)

    mac2 = aes.add_pad(sforged)
    mac2 = aes.encrypt_cbc(mac2)
    mac2 = aes.get_mac(mac2)
    puts "Forged MAC is " + mac2

    puts "Forged string and legit string have same MAC!" if mac == mac2
end

#Test harness
mactest

#The "random iv" vulnerability
randiv

iv = "\x0" * 16
key = OpenSSL::Random.random_bytes(16)

aes = AESCBC.new(iv, key)

#Legit transaction string
s = "from=42&tx_list=15:27;30:24"
mac = aes.add_pad(s)
mac = aes.encrypt_cbc(mac)
mac = aes.get_mac(mac)
puts "MAC is " + mac


#In a "controlled" situation, gather a mac for forge ^ mac
binmac =  mac.scan(/../).map { |x| x.hex.chr }.join
forge = "59:1999999999999" #16 chars = blocksize
forgemac = aes.block_xor(forge, binmac )
forgemac = aes.encrypt_cbc(forgemac)
#@puts "Forged MAC is " + forgemac.unpack("H*").join
forgemac = aes.get_mac(forgemac)
puts "Forged MAC is " + forgemac

#Craft a dodgey transaction
dodgey = aes.add_pad(s) + forge
puts "Dodgey transaction string is " + dodgey.inspect
dodgeymac = aes.encrypt_cbc(dodgey)
dodgeymac = aes.get_mac(dodgeymac)
puts "Dodgey MAC is " + dodgeymac

raise "MAC error" unless dodgeymac == forgemac
puts "Successfully created a MAC for the forged string"

