# vim: set noet:
#
# WANG - Web Access with No Grief v0.01
#	kamu - <mr.kamu@gmail.com>
# 	joux3 - <@>
#
# goal: fast & no-nonsense httplib that supports keepalive & [gz](lib|zip)
#
# TODO: 	caching system (via if-none-match/last-modified)
# 		keep-alive timeouts (probably don't need seeing as the server disconnects anyway, and we handle reconnects already)
# 		SSL (???)

require 'socket'
require 'uri'
require 'stringio'
require 'zlib'
require 'logger'
require 'yaml'
require 'timeout'

module WANG

	REDIRECTION_CODES = [301, 302, 303, 307]

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
	COOKIES = "Cookie: %s\n"
	FORM = 
"Content-Type: application/x-www-form-urlencoded
Content-Length: %s\n"
	DEFAULT_OPEN_TIMEOUT = 60
	DEFAULT_READ_TIMEOUT = 60

	def self.new(*args)
		Client.new(*args)
	end

	class TCPSocket < TCPSocket # add the timeouts
		def initialize(*args) # allows passing of the timeout values
			custom_args = args.shift
			@read_timeout = custom_args[:read_timeout]
			open_timeout = custom_args[:open_timeout]
			Timeout::timeout(open_timeout) { super }
		end

		TIMEOUT_READ = %w{read readpartial gets readline}
		TIMEOUT_READ.each {|m|
			class_eval "def #{m}(*args); Timeout::timeout(@read_timeout) { super }; end;"
		}
	end

	class Client
		attr_accessor :referer

		def initialize args = {}
			@log = Logger.new(STDOUT)
			@log.level = args[:debug] ? Logger::DEBUG : Logger::WARN

			@jar = Jar.new
			@socket = nil
			@host = nil
			@referer = URI.parse("http://www.google.com/")
			@read_timeout = args[:read_timeout] || DEFAULT_READ_TIMEOUT
			@open_timeout = args[:open_timeout] || DEFAULT_OPEN_TIMEOUT

			@log.debug("Using #{@read_timeout} as the read timeout and #{@open_timeout} as the open timeout")
		end

		def get url, referer = nil
			@log.debug("GETTING: #{url.to_s}")
			request("GET", url.is_a?(URI) ? url : URI.parse(url), referer) 
		end

		def post url, data, referer = nil
			@log.debug("POSTING: #{url.to_s}")
			request("POST", url.is_a?(URI) ? url : URI.parse(url), referer, data) 
		end

		def save_cookies file
			@jar.save(file)
		end

		def load_cookies file
			@jar.load(file)
		end

		private
		def request method, uri, referer = nil, data = nil
			uri.path = "/" if uri.path.empty? # fix the path to contain / right here, otherwise it should be added to cookie stuff too
			check_socket uri.host

			@referer = referer.nil? ? @referer : referer

			@socket << HEADERS % [
				method,
				uri.path + (uri.query.nil? ? "" : "?#{uri.query}"),
				uri.host, @referer.to_s
			]

			@socket << COOKIES % @jar.cookies_for(uri) unless @jar.cookies_for(uri).empty?
			@log.debug("SENDING COOKIES: #{@jar.cookies_for(uri)}") unless @jar.cookies_for(uri).empty?

			data = data.map {|k,v| "#{URI.encode(k)}=#{URI.encode(v)}"}.join("&") if data.is_a?(Hash)

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

			return handle_redirect(headers["location"], uri) if REDIRECTION_CODES.include?(status)
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
					@jar.consume(val, @referer)
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
			@socket = TCPSocket.new({:read_timeout=>@read_timeout, :open_timeout=>@open_timeout}, host, 'http')
			@host = host
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
			@path = uri.path if @path.nil? and uri
			@path.sub!(/\/$/, "") #remove the trailing /, because path matching automatically adds it

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

		def save file
			file << @jar.to_yaml
			file.close
		end

		def load file
			saved_jar = YAML::load(file.read)

			saved_jar.each do |c|
				add(c)
			end
		end
	end
end
