#!/usr/bin/env ruby
#technion@lolware.net
#
require 'openssl';

f = File.read('7.txt');

f = f.unpack('m').join;
puts "Length was #{f.length}";

decipher = OpenSSL::Cipher.new('AES-128-ECB')
decipher.key = "YELLOW SUBMARINE";

puts decipher.update(f) + decipher.final;

