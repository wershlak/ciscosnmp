# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ciscosnmp/version'

Gem::Specification.new do |spec|
  spec.name          = "ciscosnmp"
  spec.version       = Ciscosnmp::VERSION
  spec.authors       = ["Jeff Wolak"]
  spec.email         = ["jeffrey.wolak@gmail.com"]

  spec.summary       = %q{Tools for dealing with Cisco devices using SNMP}
  spec.description   = %q{Tools for dealing with Cisco devices using SNMP}
  spec.homepage      = "https://github.com/wershlak/ciscosnmp"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency 'snmp', '=1.2.0'
  spec.add_dependency 'ipaddress', '~> 0.8.0'

  spec.add_development_dependency "bundler", "~> 1.10"
  spec.add_development_dependency "rake", "~> 10.0"

end
