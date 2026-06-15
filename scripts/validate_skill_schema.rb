#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "yaml"

ROOT = File.expand_path("..", __dir__)
SCHEMA_PATH = File.join(ROOT, "schemas", "skill.schema.json")
DEFAULT_GLOBS = [
  File.join(ROOT, "skills", "*", "*", "SKILL.md"),
  File.join(ROOT, "roles", "*", "SKILL.md")
].freeze

def usage
  warn "Usage: ruby scripts/validate_skill_schema.rb [SKILL.md ...]"
end

def load_schema
  JSON.parse(File.read(SCHEMA_PATH))
rescue Errno::ENOENT
  abort "Schema not found: #{SCHEMA_PATH}"
rescue JSON::ParserError => e
  abort "Invalid JSON schema #{SCHEMA_PATH}: #{e.message}"
end

def skill_files(args)
  files = args.empty? ? DEFAULT_GLOBS.flat_map { |pattern| Dir.glob(pattern) } : args
  files.map { |path| File.expand_path(path, Dir.pwd) }.sort
end

def frontmatter_for(path)
  text = File.read(path)
  match = text.match(/\A---\s*\n(.*?)\n---\s*(?:\n|\z)/m)
  raise "missing YAML frontmatter delimited by ---" unless match

  YAML.safe_load(match[1], permitted_classes: [], aliases: false) || {}
rescue Psych::SyntaxError => e
  raise "invalid YAML frontmatter: #{e.message}"
end

def type_name(value)
  case value
  when String then "string"
  when Array then "array"
  when Hash then "object"
  when TrueClass, FalseClass then "boolean"
  when Integer then "integer"
  when Float then "number"
  when NilClass then "null"
  else value.class.name
  end
end

def validate_type(value, expected)
  Array(expected).include?(type_name(value))
end

def validate_string(path, value, schema, errors)
  return unless value.is_a?(String)

  min = schema["minLength"]
  errors << "#{path} must be at least #{min} characters" if min && value.length < min

  pattern = schema["pattern"]
  return unless pattern

  errors << "#{path} must match /#{pattern}/" unless Regexp.new(pattern).match?(value)
end

def validate_array(path, value, schema, errors)
  return unless value.is_a?(Array)

  min = schema["minItems"]
  errors << "#{path} must contain at least #{min} item(s)" if min && value.length < min

  item_schema = schema["items"]
  return unless item_schema

  value.each_with_index do |item, index|
    validate_value("#{path}[#{index}]", item, item_schema, errors)
  end
end

def validate_value(path, value, schema, errors)
  if schema["oneOf"]
    nested = schema["oneOf"].map do |candidate|
      candidate_errors = []
      validate_value(path, value, candidate, candidate_errors)
      candidate_errors
    end
    errors << "#{path} must match one allowed schema" if nested.none?(&:empty?)
    return
  end

  expected_type = schema["type"]
  if expected_type && !validate_type(value, expected_type)
    errors << "#{path} must be #{Array(expected_type).join(' or ')}, got #{type_name(value)}"
    return
  end

  enum = schema["enum"]
  errors << "#{path} must be one of #{enum.join(', ')}" if enum && !enum.include?(value)

  validate_string(path, value, schema, errors)
  validate_array(path, value, schema, errors)
end

def validate_document(frontmatter, schema)
  errors = []

  schema.fetch("required", []).each do |field|
    errors << "missing required field: #{field}" unless frontmatter.key?(field)
  end

  properties = schema.fetch("properties", {})
  unless schema.fetch("additionalProperties", true)
    frontmatter.each_key do |key|
      errors << "unknown field: #{key}" unless properties.key?(key)
    end
  end

  frontmatter.each do |key, value|
    next unless properties.key?(key)

    validate_value(key, value, properties[key], errors)
  end

  errors
end

def validate_name_matches_path(path, frontmatter)
  return [] unless path.include?("#{File::SEPARATOR}skills#{File::SEPARATOR}")

  expected = File.basename(File.dirname(path))
  actual = frontmatter["name"]
  actual == expected ? [] : ["name must match skill directory '#{expected}', got '#{actual}'"]
end

schema = load_schema
files = skill_files(ARGV)

if files.empty?
  usage
  abort "No SKILL.md files found."
end

failed = false
files.each do |path|
  relative = path.delete_prefix("#{ROOT}#{File::SEPARATOR}")
  begin
    frontmatter = frontmatter_for(path)
    errors = validate_document(frontmatter, schema) + validate_name_matches_path(path, frontmatter)
  rescue StandardError => e
    errors = [e.message]
  end

  if errors.empty?
    puts "OK: #{relative}"
  else
    failed = true
    puts "FAIL: #{relative}"
    errors.each { |error| puts "  - #{error}" }
  end
end

exit(failed ? 1 : 0)
