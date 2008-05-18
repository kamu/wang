# vim: set noet:
#
# WANG - Web Access with No Grief
#   http://github.com/kamu/wang/

require 'test/unit'
require 'wang'
require 'test/wang_test_server'

$test_server = WANGTestServer.new
Thread.new do
	$test_server.start
end

class WangTest < Test::Unit::TestCase
	def setup
		@client = WANG.new(:debug => true, :read_timeout=>0.9) # small read timeout shouldn't fail local tests
	end

	def test_returns_success_from_google
		status, headers, body = @client.get('http://localhost:8080/')
		assert_equal 200, status
	end

	def test_returns_headers_hash
		status, headers, body = @client.get('http://localhost:8080/')
		assert headers.is_a?(Hash)
		assert_equal 'text/html', headers['content-type']
	end

	def test_supports_custom_ports
		assert_nothing_raised { @client.get('http://localhost:8080/redirect') }
	end

	def test_follows_redirect
		status, headers, body = @client.get('http://localhost:8080/redirect')
		assert_equal 'http://localhost:8080/redirect', @client.responses.first.uri.to_s
		assert_equal 'http://localhost:8080/redirected/elsewhere', @client.responses.last.uri.to_s
		assert_equal 200, status
		assert_equal "The redirect worked.\n", body
	end

	def test_posts_data_using_query_string
		status, headers, body = @client.post('http://localhost:8080/canhaspost', 'mopar=dongs&joux3=king')
		assert_equal 200, status
		assert body =~ /mopar => dongs/
		assert body =~ /joux3 => king/
	end

	def test_posts_data_using_hash
		status, headers, body = @client.post('http://localhost:8080/canhaspost', {'mopar'=>'dongs', 'joux3'=>'king'})
		assert_equal 200, status
		assert body =~ /mopar => dongs/
		assert body =~ /joux3 => king/
	end

	def test_head_http_method
		status, headers, body = @client.head('http://localhost:8080/whatmethod')
		assert_equal 'HEAD', headers['method-used']
	end

	def test_get_http_method
		status, headers, body = @client.get('http://localhost:8080/whatmethod')
		assert_equal 'GET', headers['method-used']
	end

	def test_post_http_method
		status, headers, body = @client.post('http://localhost:8080/whatmethod', {'some' => 'query'})
		assert_equal 'POST', headers['method-used']
	end

	def test_put_http_method
		status, headers, body = @client.put('http://localhost:8080/whatmethod', {'some' => 'query'})
		assert_equal 'PUT', headers['method-used']
	end

	def test_delete_http_method
		status, headers, body = @client.delete('http://localhost:8080/whatmethod')
		assert_equal 'DELETE', headers['method-used']
	end

	def test_head_requests_return_nil_body
		status, headers, body = @client.head('http://localhost:8080/')
		assert_equal nil, body
	end

	def test_delete_requests_return_nil_body
		status, headers, body = @client.delete('http://localhost:8080/whatmethod')
		assert_equal nil, body
	end

	def test_read_timeout
		assert_raise Timeout::Error do
			@client.get('http://localhost:8080/timeout')
		end
	end

	def test_infinite_redirection
		@client.get('http://localhost:8080/infiniteredirect')
	end

	def test_cookie_domain
		cookie = WANG::Cookie.new.parse("x=y; domain=cat.com")
		assert cookie.match_domain?("cat.com")
		assert !cookie.match_domain?("cat.com.au")
		assert !cookie.match_domain?("cat,com") #just incase we are using the regexp '.'
		assert !cookie.match_domain?("dogeatcat.com")
		assert !cookie.match_domain?("ihatethat.cat.com")

		cookie = WANG::Cookie.new.parse("x=y; domain=.cat.com")
		assert cookie.match_domain?("blah.cat.com")
		assert !cookie.match_domain?("cat.com") #this is what I read in the spec
		assert !cookie.match_domain?("blah.cat.com.au")
	end

	def test_cookie_paths
		cookie = WANG::Cookie.new.parse("x=y; path=/lamo/")
		assert cookie.match_path?("/lamo")
		assert !cookie.match_path?("/lamoa")
		assert cookie.match_path?("/lamo/aaa/bb")
		assert !cookie.match_path?("/lam")
		assert !cookie.match_path?("/lam/oo")
	end

	def test_basic_auth
		status, headers, body = @client.get('http://localhost:8080/basic_auth')
		assert_equal status, 401 #unauthorized!

		@client.set_auth('tester', 'wanger')
		status, headers, body = @client.get('http://localhost:8080/basic_auth')
		assert_equal status, 200
		assert body =~ /auth successful/
	end
end
