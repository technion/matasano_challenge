#!/usr/bin/env ruby
#

def xor_thekey(i) 
    plain = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736';
	binary = plain.scan(/../).map { |x| x.hex.chr }.join;

	ret = [];
	binary.each_byte { |b| ret.push((b ^ i).chr)  };
	return  ret.join;
end

(0..255).each { |x| 
	evaluated = xor_thekey(x);
	magiccount = evaluated.scan(/[ETAOIN SHRDLU]/i).size;
	if(!/[[:cntrl:]]/.match(evaluated) && magiccount > 20)
		puts "Potential match at #{x} with #{evaluated}";
	end
}

