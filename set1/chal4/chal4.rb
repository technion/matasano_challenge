#!/usr/bin/env ruby
#technion@lolware.net

def xor_thekey(enc_string, i) 
    #Accepts a hex encoded enc_string and converts to binary
    #Then xor's that string by a single character
	binary = enc_string.scan(/../).map { |x| x.hex.chr }.join;
	ret = [];

	binary.each_byte { |b| ret.push((b ^ i).chr)  };
	return  ret.join;
end

def key_search(enc_string)
    #For a given string, searches through each single byte character for
    #a feasible decoding using the ETAOIN SHRDLU frequency
    (0..255).each { |x| 
        evaluated = xor_thekey(enc_string, x);
        evaluated = evaluated.chomp;
        magiccount = evaluated.scan(/[ETAOIN SHRDLU]/i).size;
        if(magiccount > 20)
            puts "Potential match at #{x} with '#{evaluated}' on:\n#{enc_string}";
        end

    }
end


test_cases = File.open('4.txt').read;
test_cases.each_line do |line |
    key_search(line.chomp);
end

