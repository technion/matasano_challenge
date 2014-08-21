#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'aesctr.rb'
Magic = 40

def get_ciphers
    #Reads the challenge file, b64 decodes, and encrypts every li
    f = File.open '20.txt'

    plain = []
    shortest = 9000 #Arbitrarily large
    f.each_line { |line|
        line = line.chomp
        bin = line.unpack("m").join
        shortest = bin.length if bin.length < shortest
        encrypt = AESCTR.new #Yes I did mean to recreate this every loop..
        plain.push(encrypt.endecrypt(bin))
    }
    f.close

    #Truncate all to the shortest length
    trunc = plain.map { |x| x[0..shortest-1] }
    return trunc
end

def xor_thekey(enc_string, i)
    #Then xor's that string by a single character
    ret = []
    enc_string.each_byte { |b| ret.push((b ^ i).chr)  }

    return  ret.join
end


def key_search(enc_string)
    #For a given string, searches through each single byte character for
    #a feasible decoding using the ETAOIN SHRDLU frequency
    foundkey = ""
    (0..255).each { |x|
        evaluated = xor_thekey(enc_string, x);
        magiccount = evaluated.scan(/[ETAOIN SHRDLU]/i).size;
        #Removing control characters protects us during debugging
        #evaluated = evaluated.gsub(/[\r\t\n]/, "") 
        #evaluated = evaluated.gsub(/[[:cntrl:]]/,"");
        if(magiccount > Magic)
            #puts "Potential match at #{x} counting #{magiccount} with '#{evaluated}'";
            puts "Potential match at #{x.to_s(16)} counting #{magiccount} ";
            foundkey = x
        end

    }
    return foundkey
end

def search_blocks_for_key(keysize, cipher)
    key = ""
    (0..keysize-1).each { |b|
        puts "Byte #{b}";
        block = get_block_from_file(cipher[b, cipher.length], keysize);
        key = key + key_search(block).chr;
    }
    puts key.each_byte.map { |x| '\x' + x.to_s(16) }.join
end

def get_block_from_file(f, size)
    ret = [];
    i = 0;
    until i >=f.length do
        ret.push(f[i]);
        i += size;
    end
    return ret.join;
end

ciphers = get_ciphers

keysize = ciphers[0].length

search_blocks_for_key(keysize, ciphers.join)

