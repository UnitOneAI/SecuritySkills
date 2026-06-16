#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"
require "open3"
require "tempfile"

ROOT = File.expand_path("..", __dir__)
FIXTURE_ROOT = File.join(ROOT, "tests", "fixtures")
KINDS = %w[vulnerable benign].freeze
FIXER_CATEGORIES = %w[auto-fix assisted-fix guidance-only human-review-required].freeze
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

def validate_string_list(value, prefix, errors)
  unless value.is_a?(Array) && !value.empty?
    errors << "#{prefix}: must be a non-empty array"
    return
  end

  value.each_with_index do |item, index|
    errors << "#{prefix}[#{index}]: must be a non-empty string" unless item.is_a?(String) && !item.empty?
  end
end

def path_inside_case?(path, case_dir)
  absolute_case_dir = File.expand_path(case_dir)
  absolute_path = File.expand_path(path, case_dir)

  absolute_path == absolute_case_dir || absolute_path.start_with?("#{absolute_case_dir}#{File::SEPARATOR}")
end

def validate_relative_case_file(value, field, manifest_path, case_dir, errors, must_exist: true)
  unless value.is_a?(String) && !value.empty?
    errors << "#{rel(manifest_path)}: #{field} must be a non-empty relative path"
    return nil
  end

  if value.start_with?("/") || value.split(File::SEPARATOR).include?("..") || !path_inside_case?(value, case_dir)
    errors << "#{rel(manifest_path)}: #{field} must stay inside the case directory"
    return nil
  end

  absolute_path = File.expand_path(value, case_dir)
  errors << "#{rel(manifest_path)}: #{field} does not exist: #{value}" if must_exist && !File.file?(absolute_path)
  absolute_path
end

def unified_diff(before_path, after_path, display_path)
  Tempfile.create("empty-remediation-before") do |empty|
    actual_before = File.file?(before_path) ? before_path : empty.path
    before_label = File.file?(before_path) ? "before/#{display_path}" : "/dev/null"
    after_label = "after/#{display_path}"
    stdout, _stderr, status = Open3.capture3("diff", "-u", "--label", before_label, "--label", after_label, actual_before, after_path)

    return "" if status.success?
    return stdout if [0, 1].include?(status.exitstatus)

    raise "diff failed for #{display_path}"
  end
end

def validate_remediation(manifest, manifest_path, errors)
  remediation = manifest["remediation"]
  return if remediation.nil?

  prefix = rel(manifest_path)
  case_dir = File.dirname(manifest_path)

  unless remediation.is_a?(Hash)
    errors << "#{prefix}: remediation must be an object"
    return
  end

  category = remediation["category"]
  errors << "#{prefix}: remediation.category must be one of #{FIXER_CATEGORIES.join(', ')}" unless FIXER_CATEGORIES.include?(category)
  errors << "#{prefix}: remediation.category must be auto-fix for expected diff regression cases" if category && category != "auto-fix"

  expected_files = remediation["expected_files"]
  unless expected_files.is_a?(Array) && !expected_files.empty?
    errors << "#{prefix}: remediation.expected_files must be a non-empty array"
    return
  end

  expected_files.each_with_index do |expected_file, index|
    file_prefix = "#{prefix}: remediation.expected_files[#{index}]"
    unless expected_file.is_a?(Hash)
      errors << "#{file_prefix} must be an object"
      next
    end

    path = expected_file["path"]
    before_path = validate_relative_case_file(path, "#{file_prefix}.path", manifest_path, case_dir, errors, must_exist: false)
    after_path = validate_relative_case_file(expected_file["after"], "#{file_prefix}.after", manifest_path, case_dir, errors)
    validate_string_list(expected_file["expected_diff_contains"], "#{file_prefix}.expected_diff_contains", errors)
    validate_string_list(expected_file["expected_after_contains"], "#{file_prefix}.expected_after_contains", errors) if expected_file.key?("expected_after_contains")
    next unless before_path && after_path && File.file?(after_path)

    diff_text = unified_diff(before_path, after_path, path)
    if diff_text.empty?
      errors << "#{file_prefix}: expected diff is empty"
    else
      expected_file["expected_diff_contains"].to_a.each do |snippet|
        next unless snippet.is_a?(String)

        errors << "#{file_prefix}: expected_diff_contains not found in generated diff: #{snippet.inspect}" unless diff_text.include?(snippet)
      end
    end

    after_text = File.read(after_path)
    expected_file["expected_after_contains"].to_a.each do |snippet|
      next unless snippet.is_a?(String)

      errors << "#{file_prefix}: expected_after_contains not found in #{rel(after_path)}: #{snippet.inspect}" unless after_text.include?(snippet)
    end
  end
end

remediation_only = ARGV.include?("--remediation-only")
manifests = fixture_manifests

if manifests.empty?
  warn "FAIL: no skill fixture manifests found under tests/fixtures/<skill-id>/<case-id>/manifest.yaml"
  exit 1
end

errors = []
remediation_count = 0
manifests.each do |manifest_path|
  begin
    manifest = load_manifest(manifest_path)
    next if remediation_only && !manifest.key?("remediation")

    validate_manifest_shape(manifest, manifest_path, errors)
    target_path = validate_case_paths(manifest, manifest_path, errors)
    validate_evidence(manifest, manifest_path, target_path, errors)
    validate_remediation(manifest, manifest_path, errors)
    remediation_count += 1 if manifest.key?("remediation")
  rescue StandardError => e
    errors << "#{rel(manifest_path)}: #{e.message}"
  end
end

if remediation_only && remediation_count.zero?
  errors << "no remediation regression manifests found"
end

if errors.empty?
  if remediation_only
    puts "OK: validated #{remediation_count} remediation regression fixture manifest(s)."
  else
    puts "OK: validated #{manifests.size} skill fixture manifest(s), including #{remediation_count} remediation regression fixture(s)."
  end
else
  puts "FAIL: skill fixture validation failed."
  errors.each { |error| puts "  - #{error}" }
end

exit(errors.empty? ? 0 : 1)
