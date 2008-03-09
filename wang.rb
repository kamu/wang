#
# WANG - Web Acess with No Grief v0.01
#
# goal: fast & no-nonsense httplib that supports keepalive & zlib
# TODO: perhaps implement a caching system via use of if-none-match/last-modified
# 	any comments Joux3? I can cook something like this up in a few minutes

require 'socket'
require 'uri'
require 'stringio'
require 'zlib'
require 'logger'

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
FORM = 
"Content-Type: application/x-www-form-urlencoded
Content-Length: %s\n\n%s"


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

	def get url
		@log.debug("GETTING: #{url.to_s}")
		request("GET", url.is_a?(URI) ? url : URI.parse(url)) 
	end

	#TODO (Kamu): Add post/formdata
	def post url, data, referer = nil
		request("POST", url.is_a?(URI) ? url : URI.parse(url), data) 
	end

	private
	def request method, uri, data = nil
		check_socket uri.host

		@socket << HEADERS % [
			method,
			#now will correctly GET URLs with GET Params
			uri.path.empty? ? "/" : uri.path + (uri.query.nil? ? "" : "?#{uri.query}"),
			uri.host, @referer.to_s, ""
		]

		# TODO, fix the referer crap
		# ?!?!? What is wrong with it? It works fine?
		@referer = uri

		headers = read_headers
		@log.debug("HEADERS: #{headers.inspect}")

		body = read_body(headers)

		@socket.close if headers["connection"] =~ /close/
		
		return handle_redirect(headers["location"], uri) if [301, 302, 303, 307].include?(headers['code'])
		body = decompress(headers["content-encoding"], body)

		return headers, body
	end

	def read_headers
		headers = Hash.new
		while header = @socket.gets("\n")
			header.sub!(/\r?\n/, "")
			break if header.empty?
			if header =~ /^HTTP\/1\.\d (\d+) (.*)$/
				headers['code'] = $1.to_i
			else
				pair = header.split(": ", 2)
				headers.store(pair[0].downcase, pair[1])
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
		@socket = TCPSocket.new(host, 'www')
		@host = host
	end
end

#TODO (Kamu): Add cookie+cookiejar
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
	#puts test.get("http://google.com").inspect
	
	#TODO (Joux3): Wang returns no body data for this site!?
	h, d = test.get("http://bash.org/?random1")
	puts d

end
