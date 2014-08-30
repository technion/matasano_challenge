#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'rsa.rb'

SECRET = "A par of soks for feets"

class Badserver
    def initialize
        @r = RSA.new
        @used = []
    end
    
    def getpubkeys
        #N would be communicated as part of the protocol, this wouldn't
        #likely be a real function. We just emulate that protocol.
        e, n = @r.getpubkeys
        return e, n
    end

    def encrypt(string)
        c = @r.encrypt(string)
        return c
    end

    def decrypt(blob)
        hash = OpenSSL::Digest::SHA1.digest(blob.to_s)
        if @used.include? hash
            raise "Previously used hash"
        end
        @used.push(hash)
        m = @r.decrypt(blob)
        return m
    end

end


def rsatest
    r = RSA.new
    m = SECRET + "Test Harness"
    m = r.encode(m)
    c = r.encrypt(m)
    p = r.decrypt(c)
    p = r.decode(p)
    raise "RSA encrypt/decrypt broken" if p != SECRET + "Test Harness"
end

def badservertest(server)

    rs = RSA.new
    mytext = "a piece of text"
    mytexte = rs.encode(mytext)
    blob = server.encrypt(mytexte)
    plain = server.decrypt(blob)
    plain = rs.decode(plain)
    raise "Badserver is not working" unless plain == mytext

    begin
       plain = server.decrypt(blob)
    rescue
       #Successfully failed to decrypt twice
       return
    end
    raise "Badserver not detecting duplicate hashes"
end

rsatest

server = Badserver.new
badservertest(server)
puts "Tests completed"

e,n = server.getpubkeys
raise "Getpubkeys not working" unless e == 3 #Known, hardcoded

#Another person encrypts "secret", we don't know it
rs = RSA.new #For visibility to encode/decode. It doesn't have useful keys
m = rs.encode(SECRET)
c = server.encrypt(m)

s = 14 #random > 1 mod N
chack = (s.to_bn.mod_exp(e, n) * c) % n
phack = server.decrypt(chack)
plain = (phack * rs.modinv(s, n)) % n
broken = rs.decode(plain)
raise "Incorrectly decrypted cipher" unless broken == SECRET
puts "Successfully broke: #{broken}"

 #For visibility to encode/decode. It doesn't have useful keys
