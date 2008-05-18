# vim: set noet:
#
# WANG - Web Access with No Grief
#   http://github.com/kamu/wang/

require 'webrick'
require 'stringio'

class HTTPMethodServlet < WEBrick::HTTPServlet::AbstractServlet
	%w(HEAD GET POST PUT DELETE).each do |http_method|
		define_method("do_#{http_method}") do |request, response|
			response['Method-Used'] = request.request_method
			unless request.request_method == 'DELETE'
				response.body = 'Some meaningless body'
			end
			raise WEBrick::HTTPStatus::OK
		end
	end
end

class WANGTestServer
	class BlackHole
		def <<(x)
		end
	end

	def initialize
		log = WEBrick::Log.new(BlackHole.new)
		@server = WEBrick::HTTPServer.new(:Port => 8080, :AccessLog => [], :Logger => log)

		@server.mount_proc('/redirect') do |request, response|
			response['Location'] = '/redirected/elsewhere'
			raise WEBrick::HTTPStatus::MovedPermanently
		end
		@server.mount_proc('/redirected/elsewhere') do |request, response|
			response.body = "The redirect worked.\n"
			response['Content-Type'] = 'text/plain'
			raise WEBrick::HTTPStatus::OK
		end
		@server.mount_proc('/') do |request, response|
			response.body = "<html><head><title>hi</title></head><body><p>Hullo!</p></body></html>"
			response['Content-Type'] = 'text/html'
			raise WEBrick::HTTPStatus::OK
		end
		@server.mount_proc('/canhaspost') do |request, response|
			response.body = request.query.map do |key, val|
				"#{key} => #{val}"
			end.join("\n")
			response['Content-Type'] = 'text/plain'
			raise WEBrick::HTTPStatus::OK
		end
		@server.mount_proc('/timeout') do |request, response|
			sleep 1
			raise WEBrick::HTTPStatus::OK
		end
		@server.mount_proc('/infiniteredirect') do |request, response|
			response['Location'] = '/infiniteredirect'
			raise WEBrick::HTTPStatus::TemporaryRedirect
		end
		@server.mount_proc('/basic_auth') do |request, response|
			WEBrick::HTTPAuth.basic_auth(request, response, "WANG basic HTTP auth test") {|user, pass|
				user == 'tester' && pass == 'wanger'
			}     
			response.body = "Basic auth successful!"
			raise WEBrick::HTTPStatus::OK
		end
		@htdigest = WEBrick::HTTPAuth::Htdigest.new('test/htdigest')
		@authenticator = WEBrick::HTTPAuth::DigestAuth.new(
			:UserDB => @htdigest,
			:Realm => 'WANG digest HTTP auth test'
		)
		@server.mount_proc('/digest_auth') do |request, response|	
			@authenticator.authenticate(request, response)		
			response.body = "Digest auth successful!"
			raise WEBrick::HTTPStatus::OK
		end
		@server.mount('/whatmethod', HTTPMethodServlet)
	end

	def start
		@server.start
	end

	def shutdown
		@server.shutdown
	end
end

if __FILE__ == $0
	server = WANGTestServer.new
	trap('INT') { server.shutdown }
	server.start
end
