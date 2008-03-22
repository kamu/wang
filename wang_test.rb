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
#	#st, hd, bd = test.get("http://www.whatismyip.com")
#	#st, hd, bd = test.get("http://google.com")
#	#st, hd, bd = test.get("http://bash.org/?random1")
#	#st, hd, bd = test.get('http://pd.eggsampler.com')
#	#st, hd, bd = test.post('http://emmanuel.faivre.free.fr/phpinfo.php', 'mopar=dongs&joux3=king')
#	#st, hd, bd = test.post('http://emmanuel.faivre.free.fr/phpinfo.php', {'mopar'=>'dongs', 'joux3'=>'king'})
#	#st, hd, bd = test.get("http://www.myspace.com/")
#
#	#this shit is getting seriously pro:
#	test.load_cookies(File.new("cookietest.txt", "r")) if File.exists?("cookietest.txt")
#	st, hd, bd = test.get("http://www.myspace.com/")
#	test.save_cookies(File.new("cookietest.txt", "w"))
        #puts [st, hd].inspect
#	#puts bd
#	end
