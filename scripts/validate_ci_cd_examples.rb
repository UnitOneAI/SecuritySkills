#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"
require "English"

ROOT = File.expand_path("..", __dir__)
EXAMPLE_DIR = File.join(ROOT, "examples", "ci")
YAML_EXAMPLES = %w[
  github-actions.yml
  gitlab-ci.yml
  azure-pipelines.yml
  pre-commit-config.yaml
].freeze
REQUIRED_COMMANDS = %w[
  ruby\ scripts/validate_skill_schema.rb
  ruby\ scripts/validate_index.rb
  ruby\ scripts/test_skill_fixtures.rb
].freeze

def rel(path)
  path.delete_prefix("#{ROOT}#{File::SEPARATOR}")
end

def validate_yaml(path, errors)
  document = YAML.safe_load(File.read(path), permitted_classes: [], aliases: false)
  errors << "#{rel(path)}: YAML document must be a mapping" unless document.is_a?(Hash)
rescue Psych::SyntaxError => e
  errors << "#{rel(path)}: invalid YAML: #{e.message}"
end

def validate_required_commands(path, errors)
  text = File.read(path)
  REQUIRED_COMMANDS.each do |command|
    errors << "#{rel(path)}: missing #{command}" unless text.include?(command.tr("\\", ""))
  end
end

errors = []

YAML_EXAMPLES.each do |filename|
  path = File.join(EXAMPLE_DIR, filename)
  if File.file?(path)
    validate_yaml(path, errors)
    validate_required_commands(path, errors)
  else
    errors << "#{rel(path)}: missing CI example"
  end
end

jenkinsfile = File.join(EXAMPLE_DIR, "Jenkinsfile")
if File.file?(jenkinsfile)
  validate_required_commands(jenkinsfile, errors)
  text = File.read(jenkinsfile)
  errors << "#{rel(jenkinsfile)}: missing archiveArtifacts step" unless text.include?("archiveArtifacts")
else
  errors << "#{rel(jenkinsfile)}: missing CI example"
end

local_agent = File.join(EXAMPLE_DIR, "local-agent.sh")
if File.file?(local_agent)
  validate_required_commands(local_agent, errors)
  system("bash", "-n", local_agent)
  errors << "#{rel(local_agent)}: bash syntax check failed" unless $CHILD_STATUS.success?
else
  errors << "#{rel(local_agent)}: missing local agent example"
end

if errors.empty?
  puts "OK: validated CI/CD examples."
else
  puts "FAIL: CI/CD example validation failed."
  errors.each { |error| puts "  - #{error}" }
end

exit(errors.empty? ? 0 : 1)
