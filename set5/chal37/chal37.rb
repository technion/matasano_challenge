#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl'


N = ("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
    "fffffffffffff").to_i(16)

class SRPServer
    def initialize
        #These items are pre-agreed on
        @i = "myemail"
        @p = "password"
        @g = 2
        @k = 3
    end

    def stepone
        @salt = rand(1000) 
        xh = OpenSSL::Digest::SHA256.digest(@salt.to_s + @p).unpack("H*").join
        x = xh.to_i(16)
        @v = @g.to_bn.mod_exp(x, N)
        return @salt
    end

    def getbpub
        @b = rand(1000)
        @bpub = @k * @v + @g.to_bn.mod_exp(@b, N)
    end
 
    def setkey(apub)
        uh = OpenSSL::Digest::SHA256.digest(apub.to_s + @bpub.to_s).unpack("H*").join
        u = uh.to_i(16)
        ss = (apub * @v.mod_exp(u, N)).to_bn.mod_exp(@b, N)
        puts "Server set key #{ss}"
        @k = OpenSSL::Digest::SHA256.digest(ss.to_s).unpack("H*").join
    end

    def checklogin(clientkey)
        digest = OpenSSL::Digest.new('sha256')
        h = OpenSSL::HMAC.hexdigest(digest, @k, @salt.to_s)
        return "OK" if h == clientkey
        return "ERROR"
    end
end

class SRPClient
    def initialize(salt)
        #Yes these are declared again. After all, the client shouldn't know it
        #just because the server does
        @i = "myemail"
        @p = "idonotaware"
        @g = 2
        @k = 3
        @salt = salt
    end

    def getapub
        @a = rand(1000)
        @apub = @g.to_bn.mod_exp(@a, N)
        return @apub
    end

    def setkey(bpub)
        uh = OpenSSL::Digest::SHA256.digest(@apub.to_s + bpub.to_s).unpack("H*").join
        u = uh.to_i(16)
        xh = OpenSSL::Digest::SHA256.digest(@salt.to_s + @p).unpack("H*").join
        x = xh.to_i(16)
        sc = (bpub - @k * (@g.to_bn.mod_exp(x, N))).to_bn.mod_exp(@a + u*x, N)
        @k = OpenSSL::Digest::SHA256.digest(sc.to_s).unpack("H*").join

    end

    def gethmac
        digest = OpenSSL::Digest.new('sha256')
        #S generated when A is 0 is 0. Also works when A is N or N*2
        @k = @k = OpenSSL::Digest::SHA256.digest(0.to_s).unpack("H*").join 
        h = OpenSSL::HMAC.hexdigest(digest, @k, @salt.to_s)
        return h
    end
end

server = SRPServer.new
salt = server.stepone

client = SRPClient.new(salt)
apub = client.getapub #Sets others variables in the class, do it anyway
#apub = 0 First test case
#apub = N second test case
apub = N*2 
bpub = server.getbpub

client.setkey(bpub)
server.setkey(apub)

clientkey =  client.gethmac
login = server.checklogin(clientkey)
puts login

