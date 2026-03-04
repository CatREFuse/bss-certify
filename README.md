# BSS Certify - Skill Security Assessment Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

BSS (Berry Skills Safe) Certify is a comprehensive security assessment tool for Claude Code Agent Skills. It evaluates Skills across multiple security dimensions and assigns a safety rating from S+ to D, helping users make informed decisions before installing and using Skills.

## Overview

As AI agents become more powerful, the Skills (plugins) they use require rigorous security evaluation. BSS Certify provides:

- **Multi-dimensional security analysis**: Code safety, data privacy, execution safety, dependency reliability, boundary integrity, and permission review
- **Standardized rating system**: Clear S+/S/A/B/C/D security levels
- **Source credibility assessment**: T1/T2/T3 source classification
- **Detailed certification reports**: Comprehensive reports with actionable recommendations

## Security Rating Levels

| Level | Name | Description | Recommendation |
|-------|------|-------------|----------------|
| **S+** | Verified | Highest security with manual verification | Most preferred |
| **S** | Excellent | Highly secure with trusted source | Preferred |
| **A** | Standard | Logically secure with complete boundary handling | Recommended |
| **B** | Basic | No significant issues but room for improvement | Use with caution |
| **C** | Caution | Security concerns present | Use carefully |
| **D** | Dangerous | Significant security risks | **Not recommended** |

### Rating Logic

```
D-level issue found → D (immediate veto)
C-level issue found → C
No C/D issues, not meeting A requirements → B
Meets all A requirements → A
Meets A + T1/T2 trusted source → S
Meets S + manual verification → S+
```

## Source Credibility Tiers

| Tier | Type | Examples |
|------|------|----------|
| **T1** | Official/Top-tier | Google, Microsoft, OpenAI, Anthropic, Apache Foundation |
| **T2** | Trusted Organizations | Verified org accounts, GitHub repos with >1000 stars |
| **T3** | Community/Personal | Individual developers, small community projects |

## Assessment Dimensions

### 1. Code Security
Checks for known vulnerabilities and dangerous code patterns.

**D-level triggers (veto)**:
- Using `eval()` to execute untrusted network code
- Using `exec()`, `system()` with unfiltered user input
- SQL injection, command injection, XSS vulnerabilities
- Known critical CVE vulnerabilities

### 2. Data Privacy
Examines how user data is collected, processed, and transmitted.

**D-level triggers (veto)**:
- Silent upload of local files to remote (T3 sources)
- Silent collection of passwords or keys
- Sensitive data transmitted over unencrypted channels

### 3. Execution Safety
Evaluates protective measures for operation execution.

**D-level triggers (veto)**:
- Executing `rm -rf /` or similar destructive commands
- System-level dangerous operations without confirmation
- Modifying critical system configurations without backup

### 4. Dependency Reliability
Checks the security status of external dependencies.

### 5. Boundary Integrity
Assesses handling of edge cases and exceptions.

### 6. Permission & Description Review
Reviews whether requested permissions match functionality and descriptions are accurate.

## Usage

### Basic Usage

```
/bss-certify [skill-name|github-link|local-path]
```

### Examples

```bash
# Check a skill by name
/bss-certify my-skill

# Check a skill from GitHub
/bss-certify https://github.com/user/skill-repo

# Check a local skill
/bss-certify /path/to/skill
```

## Asset Types

### Document-Only Assets
- Only Markdown, TXT, JSON/YAML config files
- No script files (Python/Node.js/Shell, etc.)
- No high-risk code blocks in Markdown
- Examples: Prompt templates, configuration collections, guides

### Code Assets
- Contains script files or executable code
- Or contains medium/high-risk code blocks in Markdown
- Requires runtime environment (Python/Node.js, etc.)
- Examples: CLI tools, automation scripts, plugins

## Sample Report Structure

```markdown
# BSS Security Certification Report

## Basic Information
- Skill Name: [name]
- Source: [GitHub link/local path]
- Source Tier: [T1/T2/T3]

## Rating Result
Rating: [S+/S/A/B/C/D]
Evaluation: [One-sentence summary]

## Check Basis
### ✅ Passed
- [Security check items passed]

### ⚠️ Notes
- [Security items to note]

### ❌ Issues
- [Security issues found]

## Detailed Check Results
[Detailed findings for each dimension]

## Usage Recommendations
[Recommended use cases and security guidelines]
```

## Installation

This Skill is designed for use with Claude Code. To install:

1. Copy the skill files to your `~/.claude/skills/` directory
2. Restart Claude Code
3. Use `/bss-certify` command to assess Skills

## Reference Documents

- [BSS Standards](references/bss-standards.md) - BSS Security Certification Standards
- [Checklist](references/checklist.md) - Security Checklist
- [Report Examples](references/report-examples.md) - Report Writing Guidelines

## Best Practices

### Before Installing a Skill

1. **Check BSS Certification Level**
   - Prefer S+/S/A rated Skills
   - Carefully evaluate risks for C/D rated Skills

2. **Verify Source Credibility**
   - Prefer T1/T2 sources
   - Carefully review code for T3 sources

3. **Read the Certification Report**
   - Pay attention to "Issues" and "Notes"
   - Understand the Skill's permission requirements

### Usage Strategy by Rating

| Rating | Personal Learning | Daily Work | Sensitive Data | Production |
|--------|------------------|------------|----------------|------------|
| S+/S | ✓ | ✓ | ✓ | ✓ |
| A | ✓ | ✓ | ✓ | ✓ |
| B | ✓ | ✓ | ⚠️ | ⚠️ |
| C | ✓ | ⚠️ | ✗ | ✗ |
| D | ✗ | ✗ | ✗ | ✗ |

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License - see LICENSE file for details

## Acknowledgments

BSS Certify is inspired by the need for trustworthy AI agent ecosystems. Special thanks to the Claude Code community for feedback and contributions.

---

*Based on BSS Security Certification Standard v1.1*
