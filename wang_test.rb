# vim: set noet:

require 'test/unit'
require 'wang'

class WangTest < Test::Unit::TestCase
	def setup
		@client = WANG.new
	end

	def test_returns_success_from_google
		status, headers, body = @client.get('http://www.google.com')
		assert_equal 200, status
	end

	def test_returns_headers_hash
		status, headers, body = @client.get('http://www.google.com')
		assert headers.is_a?(Hash)
		assert_equal 'text/html; charset=UTF-8', headers['content-type']
	end
end
