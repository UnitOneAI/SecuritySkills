#!/usr/bin/env ruby
# frozen_string_literal: true

require "set"

ROOT = File.expand_path("..", __dir__)
INDEX_PATH = File.join(ROOT, "index.yaml")
SKILL_GLOB = File.join(ROOT, "skills", "*", "*", "SKILL.md")
ROLE_GLOB = File.join(ROOT, "roles", "*", "SKILL.md")
METADATA_FIELDS = %w[tags role phase frameworks difficulty time_estimate].freeze

def rel(path)
  path.delete_prefix("#{ROOT}#{File::SEPARATOR}")
end

def parse_value(raw)
  value = raw.strip
  return nil if value.empty?

  if value.start_with?("[") && value.end_with?("]")
    inner = value[1...-1].strip
    return [] if inner.empty?

    inner.split(",").map { |item| parse_value(item) }
  elsif (value.start_with?('"') && value.end_with?('"')) ||
        (value.start_with?("'") && value.end_with?("'"))
    value[1...-1]
  elsif value == "true"
    true
  elsif value == "false"
    false
  else
    value
  end
end

def parse_index(path)
  section = nil
  current = nil
  items = { "skills" => [], "roles" => [] }

  File.readlines(path, chomp: true).each_with_index do |line, index|
    stripped = line.strip
    next if stripped.empty? || stripped.start_with?("#")

    if line =~ /^([a-z_]+):\s*$/
      section = Regexp.last_match(1)
      current = nil
      next
    end

    next unless %w[skills roles].include?(section)

    if line =~ /^  - ([A-Za-z0-9_-]+):\s*(.+?)\s*$/
      current = { "__line" => index + 1 }
      items[section] << current
      current[Regexp.last_match(1)] = parse_value(Regexp.last_match(2))
    elsif line =~ /^    ([A-Za-z0-9_-]+):\s*(.+?)\s*$/
      raise "index.yaml line #{index + 1}: field found before list item" unless current

      current[Regexp.last_match(1)] = parse_value(Regexp.last_match(2))
    end
  end

  items
rescue Errno::ENOENT
  raise "index.yaml not found at #{path}"
end

def frontmatter_for(path)
  text = File.read(path)
  match = text.match(/\A---\s*\n(.*?)\n---\s*(?:\n|\z)/m)
  raise "missing YAML frontmatter delimited by ---" unless match

  parse_frontmatter(match[1])
end

def parse_frontmatter(text)
  fields = {}
  skip_block = false

  text.each_line(chomp: true) do |line|
    if skip_block
      next if line.start_with?(" ") || line.start_with?("\t") || line.strip.empty?

      skip_block = false
    end

    next if line.strip.empty? || line.start_with?("#")
    next unless line =~ /^([A-Za-z0-9_-]+):\s*(.*?)\s*$/

    key = Regexp.last_match(1)
    raw = Regexp.last_match(2)
    if %w[| > |- >- |+ >+].include?(raw)
      skip_block = true
      next
    end

    fields[key] = parse_value(raw)
  end

  fields
end

def duplicate_values(items, field)
  counts = Hash.new(0)
  items.each { |item| counts[item[field]] += 1 if item[field] }
  counts.select { |_value, count| count > 1 }.keys
end

def compare_metadata(entry_type, id, indexed, frontmatter, errors)
  expected_name = frontmatter["name"]
  errors << "#{entry_type} #{id}: indexed id does not match frontmatter name '#{expected_name}'" if id != expected_name

  METADATA_FIELDS.each do |field|
    next unless indexed.key?(field) && frontmatter.key?(field)

    next if indexed[field] == frontmatter[field]

    errors << "#{entry_type} #{id}: #{field} mismatch; index=#{indexed[field].inspect}, frontmatter=#{frontmatter[field].inspect}"
  end
end

def validate_entries(entry_type, entries, discovered_files, errors)
  indexed_files = entries.map { |entry| entry["file"] }.compact.sort

  duplicate_values(entries, "id").each do |id|
    errors << "#{entry_type} #{id}: duplicate id in index.yaml"
  end

  duplicate_values(entries, "file").each do |file|
    errors << "#{entry_type} file #{file}: duplicate file in index.yaml"
  end

  entries.each do |entry|
    id = entry["id"]
    file = entry["file"]
    line = entry["__line"]

    errors << "#{entry_type} entry at index.yaml line #{line}: missing id" unless id
    unless file
      errors << "#{entry_type} #{id || "entry at index.yaml line #{line}"}: missing file"
      next
    end

    absolute = File.join(ROOT, file)
    unless File.file?(absolute)
      errors << "#{entry_type} #{id || file}: indexed file does not exist: #{file}"
      next
    end

    begin
      compare_metadata(entry_type, id, entry, frontmatter_for(absolute), errors) if id
    rescue StandardError => e
      errors << "#{entry_type} #{id || file}: #{file}: #{e.message}"
    end
  end

  missing_from_index = discovered_files - indexed_files
  missing_from_index.each do |file|
    errors << "#{entry_type} #{file}: file exists but is missing from index.yaml"
  end

  stale_index_entries = indexed_files - discovered_files
  stale_index_entries.each do |file|
    errors << "#{entry_type} #{file}: indexed file is outside expected #{entry_type} path set"
  end
end

def validate_role_skill_references(roles, skill_ids, errors)
  roles.each do |role|
    role.fetch("skills", []).each do |skill_id|
      next if skill_ids.include?(skill_id)

      errors << "role #{role['id']}: references unknown skill id '#{skill_id}'"
    end
  end
end

errors = []
index = parse_index(INDEX_PATH)
skill_files = Dir.glob(SKILL_GLOB).map { |path| rel(path) }.sort
role_files = Dir.glob(ROLE_GLOB).map { |path| rel(path) }.sort

validate_entries("skill", index["skills"], skill_files, errors)
validate_entries("role", index["roles"], role_files, errors) unless index["roles"].empty?
validate_role_skill_references(index["roles"], index["skills"].map { |entry| entry["id"] }.compact.to_set, errors)

if errors.empty?
  puts "OK: index.yaml matches #{skill_files.size} skills and #{role_files.size} roles."
else
  puts "FAIL: index.yaml validation failed."
  errors.each { |error| puts "  - #{error}" }
end

exit(errors.empty? ? 0 : 1)
