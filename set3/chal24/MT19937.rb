#!/usr/bin/env ruby
#technion@lolware.net

class MT19937
    Statesize = 624
    def initialize(seed)
        raise "Invalid seed type" unless seed.kind_of? Integer
        @index = Statesize
        @mt = []
        @mt.push(seed)
        (1..Statesize-1).each { |n|
            @mt[n] = (1812433253 * (@mt[n-1] ^ (@mt[n-1] >> 30)) + n) & 0xFFFFFFFF
        }
        @index = 0
    end

    def extract_numbers
       next_state if @index == 0
       y = @mt[@index]
       y ^= (y >> 11)
       y ^= (y << 7) & 0x9d2c5680
       y ^= (y << 15) & 0xefc60000
       y ^= (y >> 18)
       @index = (@index + 1) % Statesize
       return y
    end
       
    def next_state
       (0..Statesize-1).each { |n|
           y = (@mt[n] & 0x80000000) | (@mt[(n+1) % Statesize] & 0x7fffffff)
           @mt[n] = @mt[(n + 397) % Statesize] ^ (y >> 1)
           @mt[n] = @mt[n] ^ 2567483615 if y.odd?
       }
    end
end

