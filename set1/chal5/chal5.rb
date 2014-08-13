#!/usr/bin/env ruby
##technion@lolware.net

key = "ICE";
input = "Burning 'em, if you ain't quick and nimble\n";

input.length.times { |n|
	keychar = key[n % key.length].ord;
	inchar = input[n].ord;
   	input[n] = (keychar ^ inchar).chr }

puts input;

#Decrypt it using the same process
input.length.times { |n|
	keychar = key[n % key.length].ord;
	inchar = input[n].ord;
   	input[n] = (keychar ^ inchar).chr }

puts input;
