# CLAUDE.md - AI Assistant Guide

## Repository Overview

**Repository Name:** testmuhe
**Owner:** mukesh-sethu-07
**Type:** Test/Development Repository
**Current State:** Minimal setup with initial structure

This is a test repository currently in its initial development phase. This document serves as a comprehensive guide for AI assistants (like Claude) working with this codebase.

## Repository Structure

```
testmuhe/
├── .git/              # Git repository metadata
├── README.md          # Project documentation
└── CLAUDE.md          # This file - AI assistant guide
```

### Current State
- **Initial Commit:** a70ecf3
- **Files:** Minimal structure with README.md
- **Branch:** Development branches follow the pattern `claude/claude-md-<session-id>-<unique-id>`

## Development Workflows

### Git Branching Strategy

This repository uses a specific branching convention for AI-assisted development:

**Branch Naming Convention:**
- Feature branches: `claude/claude-md-<session-id>-<unique-id>`
- Example: `claude/claude-md-mhyh1ods0bvxno1n-016xDZSdbEKu28866iGpzL8u`

**Important Rules:**
1. All development must occur on designated feature branches
2. Branch names MUST start with `claude/` and end with the matching session ID
3. Pushing to incorrectly named branches will fail with 403 HTTP error
4. Never push directly to main/master without explicit permission

### Git Operations Best Practices

#### Pushing Changes
```bash
# Always use -u flag for first push
git push -u origin <branch-name>

# If network errors occur, retry up to 4 times with exponential backoff:
# - First retry: 2s delay
# - Second retry: 4s delay
# - Third retry: 8s delay
# - Fourth retry: 16s delay
```

#### Fetching/Pulling Changes
```bash
# Prefer fetching specific branches
git fetch origin <branch-name>

# For pulling
git pull origin <branch-name>

# Apply same retry logic for network failures
```

#### Commit Guidelines
- Use clear, descriptive commit messages
- Follow conventional commit format when possible
- Focus on the "why" rather than just the "what"
- Keep commits atomic and focused

### Workflow Steps

1. **Branch Creation**
   - Create feature branch following naming convention
   - Ensure branch name matches session requirements

2. **Development**
   - Make changes on the feature branch
   - Test changes thoroughly
   - Follow code conventions (see below)

3. **Commit**
   - Stage relevant changes
   - Write descriptive commit message
   - Review diff before committing

4. **Push**
   - Push to designated feature branch
   - Use `-u` flag for initial push
   - Implement retry logic for network failures

5. **Pull Request** (when applicable)
   - Create PR with comprehensive summary
   - Include test plan
   - Reference any related issues

## Code Conventions

### General Principles
- **Security First:** Avoid OWASP Top 10 vulnerabilities
  - No command injection
  - No XSS vulnerabilities
  - No SQL injection
  - Proper input validation
  - Secure authentication/authorization

- **Code Quality:**
  - Write clean, readable code
  - Follow DRY (Don't Repeat Yourself)
  - Use meaningful variable/function names
  - Add comments for complex logic
  - Keep functions focused and small

- **Testing:**
  - Write tests for new features
  - Ensure existing tests pass
  - Add edge case coverage

### File Organization
As the repository grows, maintain clear organization:
- Group related files in logical directories
- Use consistent naming conventions
- Keep configuration files at root level
- Separate source code from tests

## AI Assistant Guidelines

### Task Management
- Use TodoWrite tool for multi-step tasks
- Mark todos as in_progress before starting
- Complete todos immediately after finishing
- Only one todo should be in_progress at a time

### Tool Usage
- **File Operations:** Use Read/Write/Edit tools, not bash commands
- **Search:** Use Task tool with Explore agent for codebase exploration
- **Parallel Operations:** Execute independent operations in parallel
- **Sequential Operations:** Use `&&` for dependent operations

### Communication
- Be concise and technical
- Avoid emojis unless requested
- Focus on facts over validation
- Use code references with `file:line` format
- Don't use bash echo for communication

### Security Considerations
- Authorized security testing only
- No destructive techniques or DoS attacks
- Require clear authorization context for dual-use tools
- Educational and defensive security contexts are acceptable

## Common Tasks

### Adding New Files
1. Plan structure and naming
2. Create file using Write tool
3. Ensure proper location in directory tree
4. Update relevant documentation

### Modifying Existing Files
1. Read file first using Read tool
2. Use Edit tool for changes (preferred over Write)
3. Preserve formatting and style
4. Test changes

### Code Review
1. Check for security vulnerabilities
2. Verify code style consistency
3. Ensure tests are included
4. Review for performance issues

### Documentation
- Keep README.md updated with project changes
- Update this CLAUDE.md as repository evolves
- Document major architectural decisions
- Add inline comments for complex logic

## Environment Information

- **Platform:** Linux
- **OS Version:** Linux 4.4.0
- **Git Repository:** Yes
- **Working Directory:** /home/user/testmuhe

## GitHub Integration

**Note:** GitHub CLI (`gh`) is not available in this environment.

For GitHub operations:
- Request necessary information from users directly
- Use git commands for repository operations
- Coordinate with users for PR creation if needed

## Future Considerations

As this repository grows, consider adding:

1. **Build System**
   - Package manager configuration (package.json, requirements.txt, etc.)
   - Build scripts and automation
   - CI/CD pipeline configuration

2. **Testing Framework**
   - Unit test setup
   - Integration test structure
   - Test coverage requirements

3. **Code Quality Tools**
   - Linters and formatters
   - Pre-commit hooks
   - Code style guidelines

4. **Documentation**
   - API documentation
   - Architecture diagrams
   - Contributing guidelines
   - Changelog

5. **Project Structure**
   - Source code directories
   - Test directories
   - Configuration files
   - Asset management

## Updates and Maintenance

This document should be updated when:
- Repository structure changes significantly
- New conventions or standards are adopted
- Development workflow evolves
- New tools or frameworks are integrated
- Security policies change

---

**Last Updated:** 2025-11-14
**Document Version:** 1.0.0
**Maintained by:** AI assistants working with this repository

For questions or clarifications about this guide, consult the repository owner or recent commit history.
