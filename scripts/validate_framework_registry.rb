#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

ROOT = File.expand_path("..", __dir__)
REGISTRY_PATH = File.join(ROOT, "data", "frameworks.yaml")
REQUIRED_TOP_LEVEL = %w[schema_version last_reviewed required_families references].freeze
REQUIRED_ENTRY_FIELDS = %w[id family name version url date_reviewed owner aliases].freeze
REQUIRED_FAMILIES = %w[OWASP NIST MITRE CIS CVSS SSVC EPSS SLSA CycloneDX SPDX].freeze
DATE_PATTERN = /\A\d{4}-\d{2}-\d{2}\z/

def rel(path)
  path.delete_prefix("#{ROOT}#{File::SEPARATOR}")
end

def load_registry(errors)
  YAML.safe_load(File.read(REGISTRY_PATH), permitted_classes: [], aliases: false) || {}
rescue Errno::ENOENT
  errors << "#{rel(REGISTRY_PATH)}: missing registry"
  {}
rescue Psych::SyntaxError => e
  errors << "#{rel(REGISTRY_PATH)}: invalid YAML: #{e.message}"
  {}
end

def validate_string(value, label, errors)
  errors << "#{label} must be a non-empty string" unless value.is_a?(String) && !value.empty?
end

errors = []
registry = load_registry(errors)

REQUIRED_TOP_LEVEL.each do |field|
  errors << "#{rel(REGISTRY_PATH)}: missing top-level field #{field}" unless registry.key?(field)
end

families = registry["required_families"]
unless families.is_a?(Array)
  errors << "#{rel(REGISTRY_PATH)}: required_families must be an array"
else
  missing = REQUIRED_FAMILIES - families
  errors << "#{rel(REGISTRY_PATH)}: missing required families: #{missing.join(', ')}" unless missing.empty?
end

references = registry["references"]
unless references.is_a?(Array) && !references.empty?
  errors << "#{rel(REGISTRY_PATH)}: references must be a non-empty array"
else
  seen_ids = {}
  seen_families = Hash.new(0)
  alias_index = {}

  references.each_with_index do |entry, index|
    prefix = "#{rel(REGISTRY_PATH)}: references[#{index}]"
    unless entry.is_a?(Hash)
      errors << "#{prefix} must be an object"
      next
    end

    REQUIRED_ENTRY_FIELDS.each do |field|
      errors << "#{prefix}: missing required field #{field}" unless entry.key?(field)
    end

    %w[id family name version url date_reviewed owner].each do |field|
      validate_string(entry[field], "#{prefix}.#{field}", errors) if entry.key?(field)
    end

    if entry["id"].is_a?(String)
      errors << "#{prefix}: duplicate id #{entry['id']}" if seen_ids[entry["id"]]
      seen_ids[entry["id"]] = true
    end

    seen_families[entry["family"]] += 1 if entry["family"].is_a?(String)

    unless entry["url"].to_s.match?(%r{\Ahttps://})
      errors << "#{prefix}.url must use https://"
    end

    if entry.key?("date_reviewed") && !entry["date_reviewed"].to_s.match?(DATE_PATTERN)
      errors << "#{prefix}.date_reviewed must use YYYY-MM-DD"
    end

    aliases = entry["aliases"]
    unless aliases.is_a?(Array) && !aliases.empty?
      errors << "#{prefix}.aliases must be a non-empty array"
      next
    end

    aliases.each_with_index do |framework_alias, alias_index_in_entry|
      alias_label = "#{prefix}.aliases[#{alias_index_in_entry}]"
      validate_string(framework_alias, alias_label, errors)
      next unless framework_alias.is_a?(String)

      if alias_index[framework_alias]
        errors << "#{alias_label}: duplicate alias also used by #{alias_index[framework_alias]}"
      else
        alias_index[framework_alias] = entry["id"]
      end
    end
  end

  missing_families = REQUIRED_FAMILIES.reject { |family| seen_families[family].positive? }
  errors << "#{rel(REGISTRY_PATH)}: no reference entries for required families: #{missing_families.join(', ')}" unless missing_families.empty?
end

if errors.empty?
  puts "OK: validated framework registry with #{references.size} reference(s)."
else
  puts "FAIL: framework registry validation failed."
  errors.each { |error| puts "  - #{error}" }
end

exit(errors.empty? ? 0 : 1)
