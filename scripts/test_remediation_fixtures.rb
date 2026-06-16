#!/usr/bin/env ruby
# frozen_string_literal: true

ARGV.replace(["--remediation-only"])
load File.expand_path("test_skill_fixtures.rb", __dir__)
