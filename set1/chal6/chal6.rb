#!/usr/bin/env ruby
##technion@lolware.net

#If there was ever a case for a global variable, this  huge string used by 
#nearly every function would be it.
$data;

def hamming_distance(a, b)
    if a.length != b.length
        raise "Incompatible Hamming Distance";
    end
    ua = a.unpack('b*').join;
    ub = b.unpack('b*').join;
    diff = 0;
    ua.length.times { |n|  diff += 1 if ua[n] != ub[n] }
    return diff;
end

def open_read_file
    f = File.read('6.txt');
    return f.unpack('m').join;
end

def test_keysize(f, size)
    a = f[0..(size-1)];
    b = f[size..(size*2)-1];
    return hamming_distance(a,b);
end


def find_lowest_key
    lowesth = 9000; #artificially large
    lowestn = "";
    (2..40).each { |n|
        hamming = 0;
        b = $data.length/n; #Number of blocks
        (0..b-2).each { |k| #Process hamming for every block and average it
            hamming += test_keysize($data[n*k..$data.length], n);
        } 
        #puts "Keysize #{n} yields #{hamming.to_f/(n*b)}";;
        hamming = hamming.to_f/(n*b);
        if hamming < lowesth
            lowestn = n;
            lowesth = hamming;
        end
    }
    return lowestn;
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

def xor_thekey(enc_string, i)
    #Then xor's that string by a single character
    ret = [];

    enc_string.each_byte { |b| ret.push((b ^ i).chr)  };
    return  ret.join;
end


def key_search(enc_string)
    #For a given string, searches through each single byte character for
    #a feasible decoding using the ETAOIN SHRDLU frequency
    (0..255).each { |x|
        evaluated = xor_thekey(enc_string, x);
        magiccount = evaluated.scan(/[ETAOIN SHRDLU]/i).size;
        evaluated = evaluated.gsub(/[\r\t\n]/, ""); #Removing control characters protects us during debugging
        evaluated = evaluated.gsub(/[[:cntrl:]]/,"");
        if(magiccount > 60)
#puts "Potential match at #{x} counting #{magiccount} with '#{evaluated}'";
            puts "Potential match at #{x.chr} counting #{magiccount} ";
        end

    }
end

def search_blocks_for_key(keysize)

    (0..keysize-1).each { |b|
        puts "Byte #{b}";
        block = get_block_from_file($data[b, $data.length], keysize);
        key_search(block);
    }
end

$data = open_read_file;
keysize = find_lowest_key;
puts "Identified keysize was #{keysize}";
search_blocks_for_key(keysize);

#Debugging - outputs 272
#puts get_block_from_file("123456789012345"[1..14], keysize);

#Debugging - outputs 37
#puts hamming_distance('this is a test', 'wokka wokka!!!');
    

