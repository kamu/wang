spec = Gem::Specification.new do |s|
        s.platform = Gem::Platform::RUBY
        s.name = 'wang'
        s.version = "0.01"
        s.summary = "Web Access with No Grief."
        s.authors = ["Kamu", "Joux3"]
        s.email = "mr.kamu@gmail.com"
        s.homepage = "http://github.com/kamu/wang/tree"
        s.requirements << 'none'
        s.require_path = 'lib'
	s.files = ["rakefile", "wang.gemspec", "lib/wang.rb", "test/wang_test.rb", "test/wang_test_server.rb", "test/htdigest"]
	s.test_files = ["test/wang_test.rb"]
end

