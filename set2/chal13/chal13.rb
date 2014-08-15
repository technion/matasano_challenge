#!/usr/bin/env ruby
#technion@lolware.net
#
require 'openssl'

Blocksize = 16

def profile_for(email)
    email = email.gsub(/[=&]/,'')
    string = "email=" + email + "&uid=11&role=user"
    return string
end

def encrypt_profile(cookie)
    cipher = OpenSSL::Cipher.new('AES-128-ECB')   
    cipher.encrypt  
    cipher.key = 'O' * Blocksize
     
    enc = cipher.update(cookie) + cipher.final
    #Hex encoded return
    return enc.unpack('H*').join
end

def decrypt_profile(cookie)
    binary = cookie.scan(/../).map { |x| x.hex.chr }.join;
    cipher = OpenSSL::Cipher.new('AES-128-ECB')   
    cipher.decrypt  
    cipher.key = 'O' * Blocksize
     
    enc = cipher.update(binary) + cipher.final
    #Hex encoded return
    return enc
end

#Due a block ending in 'admin' will be padded to look like this
adminblock = "XXXXXXXXXXadmin" + "\x0b" * 11 + "@foo.com"
adminblock = profile_for(adminblock)
adminblock = encrypt_profile(adminblock)

#We want block 2, after the email=XX
adminblock = adminblock[Blocksize*2..Blocksize*4-1]
puts "Padded block starting with 'admin' is #{adminblock}"

hackedstring = "";
profile = 'user@lolware.net' 
loop do
    crackprofile = profile_for(profile)
    crackprofile = encrypt_profile(crackprofile)
    crackprofile = crackprofile[0..crackprofile.length-(Blocksize*2)-1]
    hackedstring = decrypt_profile(crackprofile + adminblock)

    break if hackedstring.match(/role=admin/)
    profile =  'a' + profile
    if profile.length > 64
        raise "Some sort of length insanity occurred"
    end
end

puts hackedstring
enc_hacked = encrypt_profile(hackedstring)
puts "Encrypted hacked string is #{enc_hacked}"
puts "Sanity: decrypted it reads #{decrypt_profile(enc_hacked)}"

