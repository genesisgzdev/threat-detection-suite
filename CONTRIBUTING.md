# Contributing Guidelines

## Code Quality Standards

All contributions must maintain the following standards:

### No Generic Code
- Every function must serve a specific purpose
- No template utilities or generic helpers
- No placeholder implementations
- No simulated or mock functions

### Real Implementations Only
- All Windows API calls must be functional and production-grade
- Proper error handling on all critical paths
- No decorative comments or unnecessary output
- Code must be self-documenting

### Development Workflow

1. Create a feature branch:
   ```
   git checkout -b feature/your-feature-name
   ```

2. Make changes with proper error handling

3. Compile and verify:
   ```
   build.bat
   ```
   or
   ```
   ./build.sh
   ```

4. Test thoroughly before submitting

5. Submit pull request with:
   - Clear description of changes
   - Verification of all error paths
   - No breaking changes to existing APIs

### Code Style

- C++17 standard
- 4-space indentation (not tabs)
- Clear variable naming
- Functions >100 lines should be split
- Add comments only for non-obvious logic

### Windows API Usage

- Always check return values
- Properly close all handles
- Use secure string functions (strcpy_s, strncpy_s)
- Validate parameters at entry points

### Testing Requirements

Before submitting:
- Compile with /W4 warnings enabled
- Test with admin privileges
- Verify all error paths
- Check for resource leaks
- Test edge cases

### Commit Messages

Format:
```
action: brief description

Detailed explanation if needed. Include:
- What was changed
- Why it was changed
- Any side effects or considerations
```

Examples:
```
add: memory anomaly detection with RWX page scanning
fix: registry cleanup error handling on protected keys
improve: LOLBin risk scoring accuracy with additional indicators
```

### Review Process

1. Code review for quality and functionality
2. Verification of Windows API correctness
3. Testing on Windows 7 SP1 and later
4. Compilation check with MSVC and MinGW

### Licensing

All contributions must be compatible with the MIT License.

By contributing, you agree that your code will be licensed under MIT.

