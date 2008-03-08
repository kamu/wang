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
DEBUG = true

class WANG
	attr_accessor :referer
	def initialize
		@jar = WANGJar.new
		@socket = nil
		@host = nil
		@referer = URI.parse("http://www.google.com/")
	end

	#TODO, perhaps add parenthesis around the params?
	def get url
		request("GET", url.is_a?(URI) ? url : URI.parse(url)) 
	end

	def post url, data, referer = nil
		request("POST", url.is_a?(URI) ? url : URI.parse(url), data) 
	end

	private
	def request method, uri, data = nil
		check_socket uri.host
		@socket << HEADERS % [method, uri.path.empty? ? "/" : uri.path , uri.host, @referer.to_s, ""]
		# invalid request if "/" isn't passed for empty path

		# TODO, fix the referer crap
		@referer = uri

		#read headers
		headers = Hash.new
		while header = @socket.gets("\n")
			header.sub!(/(\r)?\n/, "")
			puts header if DEBUG
			break if header.empty?
			if header =~ /^HTTP\/1\.\d (\d+) (.*)$/
				headers['code'] = $1.to_i
			else
				# i just had to break this, http spec defines headers case-insensitive
				pair = header.split(": ", 2)
				headers.store(pair[0].downcase, pair[1])
			end
		end
		puts headers.inspect if DEBUG

		#read the body
		#TODO split to methods, maybe
		body = ""
		if headers["transfer-encoding"] =~ /chunked/i # read chunked body
			while true
				line = @socket.readline
				chunk_len = line.slice(/[0-9a-fA-F]+/).hex
				break if chunk_len == 0
				body << @socket.read(chunk_len)
				@socket.read 2 # read the damn linechange
			end
			until (line = @socket.gets) and (line.nil? or line.sub(/\r?\n?/, "").empty?); end # read the chunk footers and the last line
			# atleast server at www.whatismyip.com has \r\n in their last line
		elsif headers["content-length"] # read body with content length
			clen = headers["content-length"].to_i
			while body.length < clen
				body << @socket.read([clen - body.length, 4096].min)
			end
		end

		@socket.close if headers["connection"] =~ /close/
		
		return handle_redirect(headers["location"], uri) if [301, 302, 303, 307].include?(headers['code'])
		body = decompress(headers["content-encoding"], body)

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
		else
			return body
		end
	end

	def check_socket host 		
		connect(host) if @socket.nil? or @socket.closed? or @host.nil? or not @host.eql? host
	end

	def connect host
		puts "Connecting to #{host}" if DEBUG
		@socket.close unless @socket.nil? or @socket.closed?
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

if __FILE__ == $0
	test = WANG.new
	# www.whatismyip.com for testing chunked & gzipped
	puts test.get("http://google.com")[0].inspect
end
