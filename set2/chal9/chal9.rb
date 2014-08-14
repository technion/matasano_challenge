#!/usr/bin/env ruby
#
def add_pad(str, size)
    if str.length > size || size > 256
        raise "String or size too long";
    end
    padlen = size - str.length;
    padlen.times { str = str.concat(padlen.chr); }
    return str;

end

padded = add_pad("YELLOW SUBMARINE", 20);
puts padded;

