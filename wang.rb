#
# WANG - Web Acess with No Grief v0.01
#
# goal: fast & no-nonsense httplib that supports keepalive & zlib
# maybes: perhaps implement a caching system via use of if-none-match/last-modified (should be fairly easy to do so!)

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
Accept-Encoding: gzip,deflate,identity
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
Keep-Alive: 300
Connection: keep-alive
Referer: %s%s\n\n\n"
COOKIES = "\nCookie: "
DEBUG = false

class WANG
	attr_accessor :referer
	def initialize
		@jar = WANGJar.new
		@socket = nil
		@host = nil
		@referer = URI.parse("http://www.google.com/")
	end

	def get url
		request("GET", url.is_a?(URI) ? url : URI.parse(url)) 
	end

	def post url, data, referer = nil
		request("POST", url.is_a?(URI) ? url : URI.parse(url), data) 
	end

	private
	def request method, uri, data = nil
		check_socket uri.host
		@socket << HEADERS % [method, uri.path, uri.host, @referer.to_s, ""]

		@referer = uri

		#i hate this, but see no nicer alternative?
		incoming = @socket.readpartial(10000000)
		headers, body = clean_data(incoming)

		puts headers.inspect if DEBUG
		return handle_redirect(headers["location"], uri) if [301, 302].include?(headers['code'])
		body = decompress(headers["content-encoding"], body)

		return headers, body
	end

	def clean_data input
		rawheaders, body = input.split("\r\n\r\n", 2)

		headers = Hash.new

		rawheaders.split(/(\r)?\n/).each do |header| # should support broken servers which just send \n
			if header =~ /^HTTP\/1\.\d (\d+) (.*)$/
				headers['code'] = $1.to_i
			else
				# i just had to break this, http spec defines headers case-insensitive
				pair = header.split(": ", 2)
				headers.store(pair[0].downcase, pair[1])
			end
		end

		return headers, body
	end

	def handle_redirect location, olduri
		puts location.inspect if DEBUG
		dest = URI.parse(location)
		unless dest.is_a?(URI::HTTP) # handle relative redirect
			dest = olduri + dest
		end
		dest.host = @referer.host if dest.host.nil?
		get(dest)
	end

	def decompress type, body
		case type
		when "gzip"
			return Zlib::GzipReader.new(StringIO.new(body)).read
		when "deflate"
			begin
				return Zlib::Inflate.inflate(body)
			rescue Zlib::DataError # check http://www.ruby-forum.com/topic/136825 for more info
				return Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(body)
			end
		when "identity"
			return body
		end
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
	def initialize raw_cookie
		@key, @value, @domain, @path, @expires = nil

	end
end

class WANGJar

end

test = WANG.new
puts test.get("http://google.com/").inspect
