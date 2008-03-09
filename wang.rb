# vim: set noet:
#
# WANG - Web Access with No Grief v0.01
#
# goal: fast & no-nonsense httplib that supports keepalive & zlib
# TODO: perhaps implement a caching system via use of if-none-match/last-modified
# 	any comments Joux3? I can cook something like this up in a few minutes

require 'socket'
require 'uri'
require 'stringio'
require 'zlib'
require 'logger'

# all the predefined headers should end with \n, so they can easily be added together
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
Referer: %s\n"
COOKIES = "Cookie: \n"
FORM = 
"Content-Type: application/x-www-form-urlencoded
Content-Length: %s\n"


class WANG
	attr_accessor :referer

	def initialize
		@log = Logger.new(STDOUT)
		@log.level = Logger::DEBUG

		@jar = WANGJar.new
		@socket = nil
		@host = nil
		@referer = URI.parse("http://www.google.com/")
	end

	def get url, referer = nil
		@log.debug("GETTING: #{url.to_s}")
		request("GET", url.is_a?(URI) ? url : URI.parse(url), referer) 
	end

	def post url, data, referer = nil
		@log.debug("POSTING: #{url.to_s}")
		request("POST", url.is_a?(URI) ? url : URI.parse(url), referer, data) 
	end

	private
	def request method, uri, referer = nil, data = nil
		check_socket uri.host

		@referer = referer.nil? ? @referer : referer

		@socket << HEADERS % [
			method,
			uri.path.empty? ? "/" : uri.path + (uri.query.nil? ? "" : "?#{uri.query}"),
			uri.host, @referer.to_s
		]
			
		data = data.map {|k,v| "#{URI.encode(k)}=#{URI.encode(v)}&"}.join.sub(/&\z/, "") if data.is_a?(Hash)

		@socket << FORM % data.length if data
		@socket << "\n"
		@socket << data if data

		@referer = uri

		status = read_status
		@log.debug("STATUS: #{status}")
		headers = read_headers
		@log.debug("HEADERS: #{headers.inspect}")
		body = read_body(headers)
		@log.debug("WANGJAR: #{@jar.inspect}")

		@socket.close if headers["connection"] =~ /close/
		
		return handle_redirect(headers["location"], uri) if [301, 302, 303, 307].include?(status)
		body = decompress(headers["content-encoding"], body)

		return status, headers, body
	end

	def read_status
		line = @socket.gets("\n")
		status = line.match(%r{^HTTP/1\.\d (\d+) })[1]
		return status.to_i
	end

	def read_headers
		headers = Hash.new
		while header = @socket.gets("\n")
			header.chomp!
			break if header.empty?

			key, val = header.split(": ", 2)
			if key =~ /^Set-Cookie2?$/i #do we dare consider set-cookie2 the same?
				@jar.consume(val)
			else
				headers.store(key.downcase, val)
			end
		end

		return headers
	end

	def read_body headers
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
		elsif headers["content-length"]
			clen = headers["content-length"].to_i
			while body.length < clen
				body << @socket.read([clen - body.length, 4096].min)
			end
		else #fallback that'll just consume all the data available 
			begin
				while true
					body << @socket.readpartial(4096)
				end
			rescue EOFError
			end
		end

		return body
	end

	def handle_redirect location, olduri
		@log.debug(location.inspect)
		dest = URI.parse(location)
		dest = olduri + dest unless dest.is_a?(URI::HTTP) # handle relative redirect
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
		@log.debug("Connecting to #{host}")
		@socket.close unless @socket.nil? or @socket.closed?
		@socket = TCPSocket.new(host, 'http')
		@host = host
	end
end

#TODO (Kamu): Finish cookie+cookiejar
class WANGCookie
	attr_accessor :key, :value, :domain, :path, :expires

	def initialize key = nil, value = nil
		@key, @value = key, value
		@domain, @path, @expires = nil
	end

	def parse raw_cookie
		keyval, *attributes = raw_cookie.split(/;\s*/)
		@key, @valuee = keyval.split("=", 2)

		attributes.each do |at|
			case at
			when /domain=(.*)/i
				@domain = $1
			when /expires=(.*)/i
				@expires = $1
			when /path=(.*)/i
				@path = $1
			end
		end

		self
	end

	def same? c
		#same cookie does not mean EQUAL cookie, could be new value&expiry for cookie in which case replace
		self.key.eql? c.key and self.domain.eql? c.domain and self.path.eql? c.path
	end

	def match? uri
		#using uri.host & uri.path, with some magic return true if relevant to the uri, false if no
	end

	def expired?
		#useless crap, but we may aswell incorporate it
	end
end

class WANGJar
	def initialize
		@jar = []
	end

	def consume raw_cookie
		cookie = WANGCookie.new.parse(raw_cookie)
		add(cookie)
	end

	def add c
		i = index(c)
		if i.nil?
			@jar << c
		else
			@jar[i] = c
		end
	end

	def cookies_for uri
		#.join("; ")
	end

	def index c
		@jar.each do |cookie|
			return @jar.index(cookie) if cookie.same? c
		end

		nil
	end

	def include? c
		not index(c).nil?
	end
end

if __FILE__ == $0
	test = WANG.new
	#st, hd, bd = test.get("http://www.whatismyip.com")
	#st, hd, bd = test.get("http://google.com")
	#st, hd, bd = test.get("http://bash.org/?random1")
	#st, hd, bd = test.get('http://pd.eggsampler.com')
	#st, hd, bd = test.post('http://emmanuel.faivre.free.fr/phpinfo.php', 'mopar=dongs&joux3=king')
	#st, hd, bd = test.post('http://emmanuel.faivre.free.fr/phpinfo.php', {'mopar'=>'dongs', 'joux3'=>'king'})
	st, hd, bd = test.get("http://www.myspace.com/")
	
	#puts [st, hd].inspect
	#puts bd
end
