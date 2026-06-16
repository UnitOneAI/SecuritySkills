#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

ROOT = File.expand_path("..", __dir__)
FIXTURE_ROOT = File.join(ROOT, "tests", "fixtures")
KINDS = %w[vulnerable benign].freeze
REQUIRED_MANIFEST_FIELDS = %w[skill case_id kind target expected_findings].freeze
REQUIRED_FINDING_FIELDS = %w[id severity evidence_contains].freeze

def rel(path)
  path.delete_prefix("#{ROOT}#{File::SEPARATOR}")
end

def load_manifest(path)
  YAML.safe_load(File.read(path), permitted_classes: [], aliases: false) || {}
rescue Psych::SyntaxError => e
  raise "invalid YAML: #{e.message}"
end

def fixture_manifests
  return [] unless Dir.exist?(FIXTURE_ROOT)

  Dir.glob(File.join(FIXTURE_ROOT, "*", "*", "manifest.yaml")).sort
end

def validate_manifest_shape(manifest, manifest_path, errors)
  unless manifest.is_a?(Hash)
    errors << "#{rel(manifest_path)}: manifest must be a YAML object"
    return
  end

  REQUIRED_MANIFEST_FIELDS.each do |field|
    errors << "#{rel(manifest_path)}: missing required field: #{field}" unless manifest.key?(field)
  end

  errors << "#{rel(manifest_path)}: kind must be one of #{KINDS.join(', ')}" if manifest["kind"] && !KINDS.include?(manifest["kind"])

  findings = manifest["expected_findings"]
  unless findings.is_a?(Array)
    errors << "#{rel(manifest_path)}: expected_findings must be an array"
    return
  end

  if manifest["kind"] == "benign" && !findings.empty?
    errors << "#{rel(manifest_path)}: benign cases must use expected_findings: []"
  end

  findings.each_with_index do |finding, index|
    prefix = "#{rel(manifest_path)}: expected_findings[#{index}]"
    unless finding.is_a?(Hash)
      errors << "#{prefix} must be an object"
      next
    end

    REQUIRED_FINDING_FIELDS.each do |field|
      errors << "#{prefix}: missing required field: #{field}" unless finding.key?(field)
    end

    unless finding.key?("cwe") || finding.key?("framework")
      errors << "#{prefix}: must include cwe or framework"
    end

    evidence = finding["evidence_contains"]
    next if evidence.nil?

    unless evidence.is_a?(String) && !evidence.empty?
      errors << "#{prefix}: evidence_contains must be a non-empty string"
    end
  end
end

def validate_case_paths(manifest, manifest_path, errors)
  case_dir = File.dirname(manifest_path)
  case_id = File.basename(case_dir)
  skill_id = File.basename(File.dirname(case_dir))

  errors << "#{rel(manifest_path)}: skill must match fixture directory '#{skill_id}'" if manifest["skill"] && manifest["skill"] != skill_id
  errors << "#{rel(manifest_path)}: case_id must match fixture directory '#{case_id}'" if manifest["case_id"] && manifest["case_id"] != case_id
  unless skill_id == "_example" || Dir.glob(File.join(ROOT, "skills", "*", skill_id, "SKILL.md")).any?
    errors << "#{rel(manifest_path)}: skill fixture directory does not match an existing skill: #{skill_id}"
  end

  target = manifest["target"]
  unless target.is_a?(String) && !target.empty?
    errors << "#{rel(manifest_path)}: target must be a non-empty relative path"
    return nil
  end

  if target.start_with?("/") || target.split(File::SEPARATOR).include?("..")
    errors << "#{rel(manifest_path)}: target must stay inside the case directory"
    return nil
  end

  target_path = File.expand_path(target, case_dir)
  unless target_path.start_with?("#{File.expand_path(case_dir)}#{File::SEPARATOR}") || target_path == File.expand_path(case_dir)
    errors << "#{rel(manifest_path)}: target must stay inside the case directory"
    return nil
  end

  errors << "#{rel(manifest_path)}: target does not exist: #{target}" unless File.file?(target_path)
  target_path
end

def validate_evidence(manifest, manifest_path, target_path, errors)
  return unless target_path && File.file?(target_path)

  findings = manifest["expected_findings"]
  return unless findings.is_a?(Array)

  target_text = File.read(target_path)
  findings.each do |finding|
    next unless finding.is_a?(Hash)

    evidence = finding["evidence_contains"]
    next unless evidence.is_a?(String)

    unless target_text.include?(evidence)
      finding_id = finding["id"] || "(missing id)"
      errors << "#{rel(manifest_path)}: finding #{finding_id} evidence_contains not found in #{rel(target_path)}"
    end
  end
end

manifests = fixture_manifests

if manifests.empty?
  warn "FAIL: no skill fixture manifests found under tests/fixtures/<skill-id>/<case-id>/manifest.yaml"
  exit 1
end

errors = []
manifests.each do |manifest_path|
  begin
    manifest = load_manifest(manifest_path)
    validate_manifest_shape(manifest, manifest_path, errors)
    target_path = validate_case_paths(manifest, manifest_path, errors)
    validate_evidence(manifest, manifest_path, target_path, errors)
  rescue StandardError => e
    errors << "#{rel(manifest_path)}: #{e.message}"
  end
end

if errors.empty?
  puts "OK: validated #{manifests.size} skill fixture manifest(s)."
else
  puts "FAIL: skill fixture validation failed."
  errors.each { |error| puts "  - #{error}" }
end

exit(errors.empty? ? 0 : 1)
