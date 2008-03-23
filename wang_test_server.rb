# vim: set noet:
require 'webrick'

class WANGTestServer
	def initialize
		@server = WEBrick::HTTPServer.new(:Port => 8080) 
		@server.mount_proc('/redirect') do |request, response|
			response['Location'] = '/redirected/elsewhere'
			raise WEBrick::HTTPStatus::MovedPermanently
		end
		@server.mount_proc('/redirected/elsewhere') do |request, response|
			response.body = "The redirect worked.\n"
			response['Content-Type'] = 'text/plain'
			raise WEBrick::HTTPStatus::OK
		end
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
