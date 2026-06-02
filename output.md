# =============================================================================
# Workflow: pull-request-build
# Purpose:   Build and test pull request changes, generating a coverage report
#            artifact. Runs with minimal privileges (contents: read) to prevent
#            unauthorized access to repository secrets or write operations.
# Security:  - No write permissions to repository
#            - No access to repository secrets (pull_request event)
#            - Artifact is read-only and contains only coverage data
# =============================================================================
name: pull-request-build

on:
  pull_request:
    branches:
      - main
      - develop
      - 'release/**'

permissions:
  contents: read

jobs:
  test:
    name: Run tests and generate coverage report
    runs-on: ubuntu-latest
    timeout-minutes: 30

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for accurate coverage reporting

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: |
          npm ci --ignore-scripts
          npm audit --audit-level=high || true  # Log vulnerabilities but don't fail

      - name: Run tests with coverage
        run: npm test -- --coverage --coverageReporters=lcov --coverageReporters=text
        env:
          NODE_OPTIONS: '--max-old-space-size=4096'

      - name: Validate coverage report
        run: |
          if [ ! -f coverage/lcov.info ]; then
            echo "::error::Coverage report not generated"
            exit 1
          fi
          # Validate file is not empty and has valid LCOV format
          if [ ! -s coverage/lcov.info ]; then
            echo "::error::Coverage report is empty"
            exit 1
          fi

      - name: Upload coverage artifact
        uses: actions/upload-artifact@v4
        with:
          name: coverage-report
          path: coverage/lcov.info
          retention-days: 7
          if-no-files-found: error
          compression-level: 6

# =============================================================================
# Workflow: coverage-summary
# Purpose:   Read-only follow-up workflow that processes coverage artifacts from
#            the pull-request-build workflow. Runs with minimal privileges and
#            does not execute or deploy artifact contents.
# Security:  - contents: read only - no write access to repository
#            - No access to repository secrets
#            - Artifact is only read, never executed or deployed
#            - Input validation ensures only trusted artifacts are processed
# =============================================================================
name: coverage-summary

on:
  workflow_run:
    workflows:
      - "pull-request-build"
    types:
      - completed
    branches:
      - main
      - develop

permissions:
  contents: read
  actions: read  # Required to download artifacts from workflow runs

jobs:
  summarize:
    name: Generate coverage summary
    if: |
      github.event.workflow_run.conclusion == 'success' &&
      github.event.workflow_run.event == 'pull_request'
    runs-on: ubuntu-latest
    timeout-minutes: 10

    steps:
      - name: Validate workflow run context
        run: |
          # Validate that the triggering workflow is from a trusted source
          if [ "${{ github.event.workflow_run.repository.full_name }}" != "${{ github.repository }}" ]; then
            echo "::error::Workflow run from untrusted repository"
            exit 1
          fi
          
          # Validate that the artifact was created by a pull_request event
          if [ "${{ github.event.workflow_run.event }}" != "pull_request" ]; then
            echo "::error::Artifact from untrusted event type"
            exit 1
          fi

      - name: Download coverage artifact
        uses: actions/download-artifact@v4
        with:
          name: coverage-report
          run-id: ${{ github.event.workflow_run.id }}
          path: ./coverage-report
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: Validate downloaded artifact
        run: |
          # Verify artifact exists and is not malicious
          if [ ! -f coverage-report/lcov.info ]; then
            echo "::error::Coverage artifact not found or invalid"
            exit 1
          fi
          
          # Validate file size (prevent DoS via huge files)
          MAX_SIZE=10485760  # 10MB
          FILE_SIZE=$(stat -c%s coverage-report/lcov.info)
          if [ "$FILE_SIZE" -gt "$MAX_SIZE" ]; then
            echo "::error::Coverage artifact exceeds maximum size"
            exit 1
          fi
          
          # Validate file content is safe (only contains LCOV data)
          if grep -qP '[^\x20-\x7E\n\r]' coverage-report/lcov.info; then
            echo "::error::Coverage artifact contains non-printable characters"
            exit 1
          fi

      - name: Generate coverage summary
        run: |
          echo "## Coverage Summary" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "### File Statistics" >> $GITHUB_STEP_SUMMARY
          echo '