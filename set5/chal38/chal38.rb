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
        #@p - password unknown as we are malicious
        @g = 2
        @k = 3
    end

    def stepone
        @salt = rand(1000) 
        #Not needed in this hack - legit calculations
        return @salt
    end

    def getbpub
        @u = 5
        @b = rand(1000)
        @bpub = @g.to_bn.mod_exp(@b, N)
        return @bpub, @u
    end
 
    def setkey(apub)
        @apub = apub
    end

    def checklogin(clientkey)
        #Small wordlist for PoC. Could easily be much bigger.
        wordlist = ['wordfails', 'madwords', 'turbowords', 'password' ]
        wordlist.each { |n|
            k = checkkey(n)
            if k == clientkey 
                return "Correctly cracked word is '#{n}'"
            end
        }
        return "Wordlist unable to find word"
    end

    def checkkey(password)
        # k = SHA256(ss) = SHA256(sc)
        # ss = (apub * @v.mod_exp(@u, N)).to_bn.mod_exp(@b, N)
        xh = OpenSSL::Digest::SHA256.digest(@salt.to_s + password).unpack("H*").join
        x = xh.to_i(16)
        v = @g.to_bn.mod_exp(x, N) #A local guess variable
        ss = (@apub * v.mod_exp(@u, N)).to_bn.mod_exp(@b, N)
        k = OpenSSL::Digest::SHA256.digest(ss.to_s).unpack("H*").join
        digest = OpenSSL::Digest.new('sha256')
        h = OpenSSL::HMAC.hexdigest(digest, k, @salt.to_s)
        return h
    end
        
end

class SRPClient
    def initialize(salt)
        #Yes these are declared again. After all, the client shouldn't know it
        #just because the server does
        @i = "myemail"
        @p = "password"
        @g = 2
        @k = 3
        @salt = salt
    end

    def getapub
        @a = rand(1000)
        @apub = @g.to_bn.mod_exp(@a, N)
        return @apub
    end

    def setkey(bpub, u)
        xh = OpenSSL::Digest::SHA256.digest(@salt.to_s + @p).unpack("H*").join
        x = xh.to_i(16)
        sc = bpub.to_bn.mod_exp(@a + u*x, N)
        @k = OpenSSL::Digest::SHA256.digest(sc.to_s).unpack("H*").join

    end

    def gethmac
        digest = OpenSSL::Digest.new('sha256')
        h = OpenSSL::HMAC.hexdigest(digest, @k, @salt.to_s)
        return h
    end
end

server = SRPServer.new
salt = server.stepone

client = SRPClient.new(salt)
apub = client.getapub 
bpub,u = server.getbpub

client.setkey(bpub, u)
server.setkey(apub)

clientkey =  client.gethmac
login = server.checklogin(clientkey)
puts login

