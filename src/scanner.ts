import { readFileSync } from 'fs'
import { glob } from 'glob'
import type { RegexMatch, SecurityIssue } from './types'
import {
  REGEX_PATTERNS,
  CATASTROPHIC_BACKTRACKING_PATTERNS,
  EXCESSIVE_QUANTIFIER_PATTERNS,
  ALTERNATION_PATTERN,
  GREEDY_QUANTIFIERS_PATTERN,
  DANGEROUS_BOUNDARIES_PATTERN,
  QUANTIFIER_PATTERN,
  SECURITY_ISSUE_TEMPLATES,
  DEFAULT_EXTENSIONS
} from './constants'

/**
 * Extracts the actual regex pattern from a match
 */
function extractRegexPattern(match: RegExpExecArray): string | null {
  // For regex literals like /pattern/flags
  if (match[0].startsWith('/')) {
    const parts = match[0].split('/')
    if (parts.length >= 3) {
      return parts.slice(1, -1).join('/')
    }
  }

  // For constructor calls, the pattern is usually in the first capture group
  return match[1] || match[0]
}

/**
 * Validates if a regex pattern is syntactically correct
 */
export function validateRegex(pattern: string): boolean {
  try {
    new RegExp(pattern)
    return true
  } catch {
    return false
  }
}

/**
 * Gets the validation error message for an invalid regex
 */
function getValidationError(pattern: string): string {
  try {
    new RegExp(pattern)
    return ''
  } catch (error) {
    return error instanceof Error ? error.message : 'Unknown validation error'
  }
}

/**
 * Checks for catastrophic backtracking patterns
 */
function hasCatastrophicBacktracking(pattern: string): boolean {
  return CATASTROPHIC_BACKTRACKING_PATTERNS.some((p) => p.test(pattern))
}

/**
 * Checks for excessive quantifiers that could lead to ReDoS
 */
function hasExcessiveQuantifiers(pattern: string): boolean {
  return EXCESSIVE_QUANTIFIER_PATTERNS.some((p) => p.test(pattern))
}

/**
 * Checks for nested quantifiers
 */
function hasNestedQuantifiers(pattern: string): boolean {
  // Look for quantifiers inside groups that are themselves quantified
  let depth = 0
  let hasQuantifierAtCurrentDepth = false

  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i]
    const nextChar = pattern[i + 1]

    if (char === '(') {
      depth++
      hasQuantifierAtCurrentDepth = false
    } else if (char === ')') {
      // Check if this group is followed by a quantifier
      if (nextChar && QUANTIFIER_PATTERN.test(nextChar)) {
        if (hasQuantifierAtCurrentDepth) {
          return true // Found nested quantifiers
        }
      }
      depth--
    } else if (depth > 0 && char && QUANTIFIER_PATTERN.test(char)) {
      hasQuantifierAtCurrentDepth = true
    }
  }

  return false
}

/**
 * General ReDoS vulnerability detection
 */
function isVulnerableToReDoS(pattern: string): boolean {
  // Look for alternation with overlapping matches
  const hasAlternation = ALTERNATION_PATTERN.test(pattern)

  // Look for greedy quantifiers
  const hasGreedyQuantifiers = GREEDY_QUANTIFIERS_PATTERN.test(pattern)

  // Look for word boundaries that might be exploited
  const hasPotentiallyDangerousBoundaries = DANGEROUS_BOUNDARIES_PATTERN.test(pattern)

  return hasAlternation && hasGreedyQuantifiers && hasPotentiallyDangerousBoundaries
}

/**
 * Analyzes regex patterns for potential security vulnerabilities
 */
export function analyzeSecurityIssues(pattern: string): SecurityIssue[] {
  const issues: SecurityIssue[] = []

  // Check for catastrophic backtracking patterns
  if (hasCatastrophicBacktracking(pattern)) {
    issues.push({
      type: 'catastrophic_backtracking',
      ...SECURITY_ISSUE_TEMPLATES.catastrophic_backtracking
    })
  }

  // Check for excessive quantifiers
  if (hasExcessiveQuantifiers(pattern)) {
    issues.push({
      type: 'excessive_quantifiers',
      ...SECURITY_ISSUE_TEMPLATES.excessive_quantifiers
    })
  }

  // Check for nested quantifiers
  if (hasNestedQuantifiers(pattern)) {
    issues.push({
      type: 'nested_quantifiers',
      ...SECURITY_ISSUE_TEMPLATES.nested_quantifiers
    })
  }

  // General ReDoS vulnerability check
  if (isVulnerableToReDoS(pattern)) {
    issues.push({
      type: 'redos',
      ...SECURITY_ISSUE_TEMPLATES.redos
    })
  }

  return issues
}

/**
 * Scans content for regex patterns
 */
export function scanContent(content: string, filePath: string): RegexMatch[] {
  const matches: RegexMatch[] = []
  const lines = content.split('\n')

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex]
    if (line === undefined) continue
    const lineNumber = lineIndex + 1

    for (const pattern of REGEX_PATTERNS) {
      pattern.lastIndex = 0 // Reset regex state
      let match

      while ((match = pattern.exec(line)) !== null) {
        const regexPattern = extractRegexPattern(match)
        if (regexPattern) {
          const regexMatch: RegexMatch = {
            pattern: regexPattern,
            file: filePath,
            line: lineNumber,
            column: match.index + 1,
            context: line.trim(),
            isValid: validateRegex(regexPattern),
            securityIssues: analyzeSecurityIssues(regexPattern)
          }

          if (!regexMatch.isValid) {
            regexMatch.validationError = getValidationError(regexPattern)
          }

          matches.push(regexMatch)
        }
      }
    }
  }

  return matches
}

/**
 * Scans a single file for regex patterns
 */
export function scanFile(filePath: string): RegexMatch[] {
  try {
    const content = readFileSync(filePath, 'utf-8')
    return scanContent(content, filePath)
  } catch (error) {
    console.warn(`Warning: Could not read file ${filePath}: ${error}`)
    return []
  }
}

/**
 * Scans files for regex patterns
 */
export async function scanDirectory(
  directory: string,
  extensions: string[] = DEFAULT_EXTENSIONS
): Promise<RegexMatch[]> {
  const matches: RegexMatch[] = []

  for (const pattern of extensions) {
    const files = await glob(pattern, { cwd: directory, absolute: true })

    for (const file of files) {
      const fileMatches = scanFile(file)
      matches.push(...fileMatches)
    }
  }

  return matches
}
