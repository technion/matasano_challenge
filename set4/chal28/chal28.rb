#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'sha1'

def keyed_sha1(string)
    #Implements a secret key in a SHA
    key = 'AA'
    return SHA1.hexdigest(key + string)

end

puts keyed_sha1("abc")
puts keyed_sha1("bbbbb")

