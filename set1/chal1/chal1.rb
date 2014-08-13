#!/usr/bin/env ruby
#
def hex_b64_conversion
    input = gets;

    #Converts hex to binary
    binary = input.scan(/../).map { |x| x.hex.chr }.join;
    #Prints the string as hex
    b64 = [binary].pack('m0');
    puts b64;
end

hex_b64_conversion;

