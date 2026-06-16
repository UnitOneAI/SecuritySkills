#!/usr/bin/env ruby
# frozen_string_literal: true

ROOT = File.expand_path("..", __dir__)
CODEOWNERS_PATH = File.join(ROOT, ".github", "CODEOWNERS")
REQUIRED_PATTERNS = {
  "AppSec" => "skills/appsec/",
  "Cloud" => "skills/cloud/",
  "AI Security" => "skills/ai-security/",
  "Compliance" => "skills/compliance/",
  "SecOps" => "skills/secops/"
}.freeze

def rel(path)
  path.delete_prefix("#{ROOT}#{File::SEPARATOR}")
end

errors = []

unless File.file?(CODEOWNERS_PATH)
  errors << "#{rel(CODEOWNERS_PATH)}: missing CODEOWNERS file"
else
  entries = File.readlines(CODEOWNERS_PATH, chomp: true)
                .map(&:strip)
                .reject { |line| line.empty? || line.start_with?("#") }

  REQUIRED_PATTERNS.each do |domain, pattern|
    entry = entries.find { |line| line.split(/\s+/).first == pattern }
    if entry.nil?
      errors << "#{rel(CODEOWNERS_PATH)}: missing #{domain} owner pattern #{pattern}"
      next
    end

    owners = entry.split(/\s+/)[1..] || []
    errors << "#{rel(CODEOWNERS_PATH)}: #{pattern} must list at least one owner" if owners.empty?
  end
end

if errors.empty?
  puts "OK: CODEOWNERS includes required domain review gates."
else
  puts "FAIL: CODEOWNERS validation failed."
  errors.each { |error| puts "  - #{error}" }
end

exit(errors.empty? ? 0 : 1)
