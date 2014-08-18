#!/usr/bin/env ruby
#technion@lolware.net

def check_pad(str)
    last = str[-1,1]
    
    padstr = last.chr * last.ord

    #unless str.match(/#{padstr}/)
    padstr = Regexp.escape(padstr)
    unless /#{padstr}\B/.match(str)
        raise "Invalid padding"
    end

end

check_pad("ICE ICE BABY\x04\x04\x04\x04")
puts "Successful first run"

begin
    check_pad("ICE ICE BABY\x04\x04\x04\x05") 
rescue StandardError
    puts "Corectly raised an error"
end
