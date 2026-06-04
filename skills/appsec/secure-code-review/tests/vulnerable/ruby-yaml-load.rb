require 'yaml'

# VULNERABLE: YAML.load can instantiate objects from attacker-controlled input.
raw_settings = params[:settings].to_s
settings = YAML.load(raw_settings)

puts settings['theme']
