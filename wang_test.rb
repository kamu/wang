# vim: set noet:

require 'test/unit'
require 'wang'
require 'wang_test_server'

$test_server = WANGTestServer.new
Thread.new do
	$test_server.start
end

class WangTest < Test::Unit::TestCase
	def setup
		@client = WANG.new(:debug => true)
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
end

#if __FILE__ == $0
#	test = WANG.new({:open_timeout=>5})
#	st, hd, bd = test.get("http://www.whatismyip.com")
#	st, hd, bd = test.get("http://google.com")
#	st, hd, bd = test.get("http://bash.org/?random1")
#	st, hd, bd = test.get('http://pd.eggsampler.com')
#	st, hd, bd = test.get("http://www.myspace.com/")
#
#	#this shit is getting seriously pro:
#	test.load_cookies(File.new("cookietest.txt", "r")) if File.exists?("cookietest.txt")
#	st, hd, bd = test.get("http://www.myspace.com/")
#	test.save_cookies(File.new("cookietest.txt", "w"))
#	puts [st, hd].inspect
#	puts bd
#end
