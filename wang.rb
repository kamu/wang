#
# WANG - Web Acess with No Grief
#
# goal: fast & no-nonsense httplib that supports keepalive & zlib

require 'socket'
require 'uri'
require 'stringio'
require 'zlib'

HEADERS = 
"%s %s HTTP/1.1
Host: %s
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.12) Gecko/20080201 Firefox/2.0.0.12
Accept: application/x-shockwave-flash,text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip,deflate
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
Keep-Alive: 300
Connection: keep-alive
Referer: %s%s\n\n\n"
COOKIES = "\nCookie: "

class WANG
	attr_accessor :referer
	def initialize
		@jar = WANGJar.new
		@socket = nil
		@host = nil
		@referer = "http://www.google.com"
	end

	def get url
		request("GET", URI.parse(url)) 
	end

	def post url, data, referer = nil
		request("POST", URI.parse(url), data) 
	end

	private
	def request method, uri, data = nil
		check_socket uri.host
		@socket << HEADERS % [method, uri.path, uri.host, @referer, ""]

		@referer = uri.to_s

		#i hate this, but see no nicer alternative?
		incoming = @socket.readpartial(10000000)
		rawheaders, body = incoming.split("\r\n\r\n", 2)

		headers = Hash.new

		rawheaders.split("\r\n").each do |header| 
			if header =~ /^HTTP\/1\.\d (\d+) (.*)$/
				headers['code'] = $1
			else
				headers.store(*header.split(": ", 2))
			end
		end

		body = Zlib::GzipReader.new(StringIO.new(body)).read if headers["Content-Encoding"].eql? "gzip"

		return headers, body
	end

	def check_socket host
		connect(host) if @socket.nil? or @socket.closed? or @host.nil? or not @host.eql? host
	end

	def connect host
		@socket.close unless @socket.nil?
		@socket = TCPSocket.new(host, 'www')
		@host = host
	end
end

class WANGCookie

end

class WANGJar

end

test = WANG.new
puts test.get("http://p34r.org/test.html").inspect
