#!/usr/bin/env ruby

key = '686974207468652062756c6c277320657965';
input = gets;

puts (key.hex ^ input.hex).to_s(16) 
