# frozen_string_literal: true

require "minitest/autorun"
require "yaml"

class ServerlessFunctionSecuritySkillTest < Minitest::Test
  SKILL_PATH = File.expand_path(
    "../skills/config/serverless-function-security/SKILL.md",
    __dir__
  )

  REQUIRED_RULES = %w[
    SF-001
    SF-002
    SF-003
    SF-004
    SF-005
    SF-006
  ].freeze

  REQUIRED_SECTIONS = [
    "# Serverless Function Security Review",
    "## Safety and Assessment Boundary",
    "## Required Evidence Collection",
    "## Detection Rules",
    "## Review Procedure",
    "## Severity Model",
    "## Required Finding Format",
    "## Normalized JSON Output"
  ].freeze

  def setup
    assert File.file?(SKILL_PATH), "missing skill at #{SKILL_PATH}"

    @content = File.read(SKILL_PATH, encoding: "UTF-8")
    @frontmatter, @body = parse_frontmatter(@content)
  end

  def test_frontmatter_has_expected_identity
    assert_equal "serverless-function-security", @frontmatter.fetch("name")
    assert_equal "1.0.0", @frontmatter.fetch("version")
    assert_equal "intermediate", @frontmatter.fetch("difficulty")
    assert_equal "unitoneai", @frontmatter.fetch("author")
  end

  def test_frontmatter_declares_safe_read_only_tools
    assert_equal ["Read", "Grep", "Glob"], @frontmatter.fetch("allowed-tools")
    assert_equal true, @frontmatter.fetch("injection-hardened")
  end

  def test_frontmatter_covers_expected_languages_and_platforms
    description = @frontmatter.fetch("description")

    %w[AWS Lambda Azure Google Terraform JavaScript Python].each do |term|
      assert_includes description, term
    end
  end

  def test_contains_all_required_review_sections
    REQUIRED_SECTIONS.each do |section|
      assert_includes @body, section
    end
  end

  def test_contains_each_detection_rule_once
    REQUIRED_RULES.each do |rule|
      occurrences = @body.scan(/^### #{Regexp.escape(rule)}:/).length
      assert_equal 1, occurrences, "#{rule} must have exactly one detection section"
    end
  end

  def test_detects_unauthenticated_function_urls_and_public_invokers
    assert_includes @body, "AuthType: NONE"
    assert_includes @body, 'Principal: "*"'
    assert_includes @body, "allUsers"
    assert_includes @body, "Anonymous"
    assert_includes @body, "SF-001"
  end

  def test_detects_admin_and_wildcard_execution_identity
    assert_includes @body, "AdministratorAccess"
    assert_includes @body, 'Action: "*"'
    assert_includes @body, "roles/owner"
    assert_includes @body, "SF-002"
  end

  def test_requires_secret_redaction_and_secret_store_remediation
    assert_includes @body, "Never print secret values"
    assert_includes @body, "secret manager"
    assert_includes @body, "SF-003"
  end

  def test_requires_event_provenance_and_replay_controls
    assert_includes @body, "signature verification"
    assert_includes @body, "idempotency"
    assert_includes @body, "dead-letter"
    assert_includes @body, "SF-004"
  end

  def test_covers_temp_storage_concurrency_and_dependency_provenance
    assert_includes @body, "/tmp"
    assert_includes @body, "concurrency"
    assert_includes @body, "digest-pinned images"
    assert_includes @body, "SF-005"
    assert_includes @body, "SF-006"
  end

  def test_declares_normalized_json_contract
    assert_includes @body, '"schema_version": "1.0"'
    assert_includes @body, '"skill": "serverless-function-security"'
    assert_includes @body, '"test_strategy"'
    assert_includes @body, "critical`, `high`, `medium`, `low`"
  end

  private

  def parse_frontmatter(content)
    match = content.match(/\A---\s*\n(.*?)\n---\s*\n(.*)\z/m)
    refute_nil match, "SKILL.md must begin with YAML frontmatter"

    frontmatter = YAML.safe_load(
      match[1],
      permitted_classes: [],
      permitted_symbols: [],
      aliases: false
    )

    assert_kind_of Hash, frontmatter
    [frontmatter, match[2]]
  end
end
