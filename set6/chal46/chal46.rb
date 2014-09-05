#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl'
require_relative 'rsa'

r = RSA.new

text = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="

text = text.unpack('m').join

cipher = r.encode(text)
cipher = r.encrypt(cipher)

e,n = r.getpubkeys
min = 0
max = n

while min != max
    cipher = (2**e * cipher) % n
    parity = r.parity_oracle(cipher)
    if parity == 0
        max -= (max-min)/2
    else
        min += (max-min)/2
    end
    break if (max - min) == 1
    puts max
end

#There are some rounding issues to sort out. Try a few possibles
(-2..2).each { |i|
    plain = r.decode(max + i)
    puts plain
}

