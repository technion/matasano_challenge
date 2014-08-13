#!/usr/bin/env ruby
##technion@lolware.net

#key = "ICE";
key = [];

#The debug key - "ICE"
#key.push(73.chr);
#key.push(67.chr);
#key.push(69.chr);
#
key = "Terminator X: Bring the noise";

#The debug filename
input = File.read('6.txt');
#input = File.read('test.b64');
input = input.unpack('m').join

input.length.times { |n|
    keychar = key[n % key.length].ord;
    inchar = input[n].ord;
    input[n] = (keychar ^ inchar).chr }
    
#output = input.gsub(/[[:cntrl:]]/," ");
#output = output.gsub(/[\r\t\n]/," ");
puts input;

exit;

#This is only useful in debug mode.
#Decrypt it using the same process
input.length.times { |n|
    keychar = key[n % key.length].ord;
    inchar = input[n].ord;
    input[n] = (keychar ^ inchar).chr }

puts input;
