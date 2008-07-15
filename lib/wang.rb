# vim: set noet:
#
# WANG - Web Access with No Grief
#   http://github.com/kamu/wang/

require 'socket'
require 'uri'
require 'stringio'
require 'zlib'
require 'logger'
require 'yaml'
require 'timeout'
require 'base64'

class URI::Generic
	def to_uri
		self
	end
end

class String
	def to_uri
		URI.parse(self)
	end
end

module WANG
	Response = Struct.new(:method, :uri, :status, :headers)

	DEFAULT_OPEN_TIMEOUT = 60
	DEFAULT_READ_TIMEOUT = 60
	INFINITE_REDIR_COUNT = 7

	# Creates a new instance of WANG::Client
	#
	# For more info, check WANG::Client.new 
	def self.new *args
		Client.new(*args)
	end

	class TCPSocket < TCPSocket # add the timeouts :nodoc:
		def initialize *args # allows passing of the timeout values
			custom_args = args.shift
			@read_timeout = custom_args[:read_timeout]
			open_timeout = custom_args[:open_timeout]
			Timeout::timeout(open_timeout) { super }
		end

		TIMEOUT_READ = %w{read readpartial gets readline eof?}
		TIMEOUT_READ.each {|m|
			class_eval "def #{m}(*args); Timeout::timeout(@read_timeout) { super }; end;"
		}
	end

	class Client
		attr_accessor :responses

		# Creates a new instance of WANG::Client
		# 
		# Accepts a hash containing named arguments. Arguments:
		# [:read_timeout] defines the timeout for socket reading in seconds
		# [:open_timeout] defines the timeout for connecting in seconds
		# [:debug] any value passed defines debug mode
		# [:proxy_address] defines the proxy address to use for all the requests made (host:port)
		# [:no_keepalive] any value passed will disable keep-alive
		def initialize args = {}
			@log = Logger.new(STDOUT)
			@log.level = args[:debug] ? Logger::DEBUG : Logger::WARN

			@jar = Jar.new
			@socket = nil
			@host, @port = nil, nil # create a struct that combines host & port?
			@responses = []
			@read_timeout = args[:read_timeout] || DEFAULT_READ_TIMEOUT
			@open_timeout = args[:open_timeout] || DEFAULT_OPEN_TIMEOUT
			@proxy_host, @proxy_port = args[:proxy_address] ? args[:proxy_address].split(':', 2) : [nil, nil]
			@no_keepalive = args[:no_keepalive]

			@log.debug("Connecting through a proxy: #{@proxy_host}:#{@proxy_port}") if @proxy_host
			@log.debug("Using #{@read_timeout} as the read timeout and #{@open_timeout} as the open timeout")
		end

		# Issues a HEAD request.
		#
		# Returns +nil+ for the body.
		def head url, referer = nil
			@log.debug("HEAD: #{url.to_s}")
			request('HEAD', url.to_uri, referer)
		end

		# Fetches a page using GET method
		#
		# If passed, referer will be sent to the server. Otherwise the last visited URL will be sent to the server as the referer.
		def get url, referer = nil
			@log.debug("GET: #{url.to_s}")
			request("GET", url.to_uri, referer)
		end

		# Fetches a page using POST method
		#
		# Data can either be a String or a Hash. If passed a String, it will send it to the server as the POST data. If passed a Hash, it will be converted to post data and correctly escaped.
		#
		# If passed, referer will be sent to the server. Otherwise the last visited URL will be sent to the server as the referer.
		def post url, data, referer = nil
			@log.debug("POST: #{url.to_s}")
			request("POST", url.to_uri, referer, data)
		end

		# Issues a PUT request. See post for more details.
		def put url, data, referer = nil
			@log.debug("PUT: #{url.to_s}")
			request("PUT", url.to_uri, referer, data)
		end

		# Issues a DELETE request.
		#
		# Returns +nil+ for the body.
		def delete url, referer = nil
			@log.debug("DELETE: #{url.to_s}")
			request("DELETE", url.to_uri, referer)
		end

		# Saves cookie from this Client instance's Jar to the given io
		def save_cookies io
			@jar.save(io)
		end

		# Loads cookies to this Client instance's Jar from the given io
		def load_cookies io
			@jar.load(io)
		end

		# Sets the HTTP authentication username & password, which are then used for requests
		# Call with +nil+ as username to remove authentication
		def set_auth username, password=''
			@http_auth = username ? Base64.encode64(username+':'+password).chomp : nil # for some reason, encode64 might add a \n
		end

		private
		def request method, uri, referer = nil, data = nil
			uri.path = "/" if uri.path.empty? # fix the path to contain / right here, otherwise it should be added to cookie stuff too
			uri = @responses.last.uri + uri unless uri.is_a?(URI::HTTP) # if the uri is relative, combine it with the uri of the latest response
			check_socket *(@proxy_host ? [@proxy_host, @proxy_port] : [uri.host, uri.port])

			referer = referer || @responses.last.nil? ? nil : @responses.last.uri
			@responses.clear if not @responses.empty? and not redirect?(@responses.last.status)

			#http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3
			#there's no defined redir count that's considered infinite, so try something that makes sense
			if @responses.length > INFINITE_REDIR_COUNT
				return #raise an error?
			end

			@socket << generate_request_headers(method, uri, referer)
			@socket << "Authorization: Basic #{@http_auth}\r\n" if @http_auth

			if @jar.has_cookies_for?(uri)
				@socket << "Cookie: #{@jar.cookies_for(uri)}\r\n"
				@log.debug("SENDING COOKIES: #{@jar.cookies_for(uri)}")
			end

			data = data.map {|k,v| "#{Utils.escape(k)}=#{Utils.escape(v)}"}.join("&") if data.is_a?(Hash)

			if data
				@socket << "Content-Type: application/x-www-form-urlencoded\r\n"
				@socket << "Content-Length: #{data.length}\r\n"
			end
			@socket << "\r\n"
			@socket << data if data

			if @socket.eof? #this is the first place after connection start where checking for eof is safe, because we can expect data
				@socket.close unless @socket.closed?
				@log.debug("EOF detected, retrying")
				return request method, uri, referer, data
			end

			status = read_status
			@log.debug("STATUS: #{status}")
			headers = read_headers(uri)
			@log.debug("HEADERS: #{headers.inspect}")
			body = read_body(headers) if returns_body?(method)
			@log.debug("WANGJAR: #{@jar.inspect}")

			@socket.close if headers["connection"] =~ /close/ or @no_keepalive

			@responses << Response.new(method, uri, status, headers)
			return follow_redirect(headers["location"]) if redirect?(status)

			body &&= decompress(headers["content-encoding"], body)

			return status, headers, body
		end

		def generate_request_headers request_method, uri, referer
			request_path = uri.path + (uri.query.nil? ? '' : "?#{uri.query}")
			request_host = uri.host + ((uri.port && uri.port != 80) ? ":#{uri.port}" : '')
			[
				"#{request_method} #{@proxy_host ? uri.to_s : request_path} HTTP/1.1",
				"Host: #{request_host}",
				"User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9) Gecko/2008052906 Firefox/3.0",
				"Accept: application/x-shockwave-flash,text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
				"Accept-Language: en-us,en;q=0.5",
				"Accept-Encoding: gzip,deflate",
				"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7",
				"Keep-Alive: 300",
				"Connection: #{@no_keepalive ? "close" : "keep-alive"}",
				referer.nil? ? "" : "Referer: #{referer}\r\n" # an extra \r\n is needed for the last entry
			].join("\r\n")
		end

		def read_status
			line = @socket.gets("\n")
			status = line.match(%r{^HTTP/1\.\d (\d+) })[1]
			return status.to_i
		end

		def read_headers uri
			headers = Hash.new
			key = nil # allow using the latest key when appending multiline headers
			while header = @socket.gets("\n")
				header.chomp!
				break if header.empty?
				if header =~ /^\s/
					headers[key] << header.strip
				else
					key, val = header.split(": ", 2)
					if key =~ /^Set-Cookie2?$/i #do we dare consider set-cookie2 the same?
						@jar.consume(val, uri)
					else
						headers.store(key.downcase, val)
					end
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
					while chunk_len > 0 # make sure to read the whole chunk
						buf = @socket.read(chunk_len)
						chunk_len -= buf.length
						body << buf
					end
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

		# Given an HTTP status code, returns whether it signifies a redirect.
		def redirect? status
			status.to_i / 100 == 3
		end

		# Given an HTTP method, returns whether a body should be read.
		def returns_body? request_method
			not ['HEAD', 'DELETE'].include?(request_method)
		end

		def follow_redirect location
			@log.debug("Redirect to #{location.inspect}")
			dest = location.to_uri
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

		def check_socket host, port = 'http'
			connect(host, port) if @socket.nil? or @socket.closed? or @host.nil? or not @host.eql? host or @port.nil? or not @port.eql? port
		end

		def connect host, port
			@log.debug("Connecting to #{host}:#{port}")
			@socket.close unless @socket.nil? or @socket.closed?
			@socket = TCPSocket.new({:read_timeout => @read_timeout, :open_timeout => @open_timeout}, host, port)
			@host = host
			@port = port
		end
	end

	class Cookie
		attr_accessor :key, :value, :domain, :path, :expires

		def initialize key = nil, value = nil
			@key, @value = key, value
			@domain, @path, @expires = nil
		end

		def parse raw_cookie, uri = nil
			keyval, *attributes = raw_cookie.split(/;\s*/)
			@key, @value = keyval.split("=", 2)

			attributes.each do |at|
				case at
				when /domain=(.*)/i
					@domain = $1
				when /expires=(.*)/i
					@expires = begin
					   Time.parse($1)
				   	rescue
					   nil
					end
				when /path=(.*)/i
					@path = $1
				end
			end

			@domain = uri.host if @domain.nil? and uri
			@path = "/" if @path.nil? and uri
			@path.sub!(/\/$/, "") if @path #remove the trailing /, because path matching automatically adds it

			self
		end

		def same? c
			self.key.eql? c.key and self.domain.eql? c.domain and self.path.eql? c.path
		end

		def match? uri
			match_domain?(uri.host) and match_path?(uri.path)
		end

		def expired?
			@expires.is_a?(Time) ? @expires < Time.now : false
		end

		def match_domain? domain # TODO check if this fully follows the spec
			case @domain
			when /^\d+\.\d+\.\d+\.\d+$/ # ip address
				domain.eql?(@domain)
			when /^\./ # so domain = site.com and subdomains could match @domain to .site.com
				domain =~ /#{Regexp.escape(@domain)}$/i
			else
				domain.downcase.eql?(@domain.downcase)
			end
		end

		def match_path? path
			path =~ /^#{Regexp.escape(@path)}(?:\/.*)?$/
		end
	end

	class Jar
		def initialize
			@jar = []
		end

		def consume raw_cookie, uri = nil
			cookie = Cookie.new.parse(raw_cookie, uri)
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

		def has_cookies_for? uri
			not cookies_for(uri).empty?
		end

		def cookies_for uri
			@jar -= @jar.select { |c| c.expired? }
			@jar.select { |c| c.match?(uri) }.map{ |c| "#{c.key}=#{c.value}" }.join("; ")
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

		def save io
			io << @jar.to_yaml
			io.close
		end

		def load io
			saved_jar = YAML::load(io)

			saved_jar.each do |c|
				add(c)
			end
		end
	end

	module Utils
		# URL-encode a string.
		def self.escape string
			string.to_s.gsub(/([^ a-zA-Z0-9_.-]+)/n) do
				'%' + $1.unpack('H2' * $1.size).join('%').upcase
			end.tr(' ', '+')
		end
			
		# URL-decode a string.
		def self.unescape string
			string.to_s.tr('+', ' ').gsub(/((?:%[0-9a-fA-F]{2})+)/n) do
				[$1.delete('%')].pack('H*')
			end
		end
	end
end
