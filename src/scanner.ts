import { readFileSync } from 'fs'
import { glob } from 'glob'

export interface RegexMatch {
  pattern: string
  file: string
  line: number
  column: number
  context: string
  isValid: boolean
  validationError?: string
  securityIssues: SecurityIssue[]
}

export interface SecurityIssue {
  type: 'redos' | 'catastrophic_backtracking' | 'excessive_quantifiers' | 'nested_quantifiers'
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  recommendation: string
}

const REGEX_PATTERNS = [
  // JavaScript/TypeScript regex literals
  /\/(?![*+?])(?:[^\r\n[/\\]|\\.|\[(?:[^\r\n\]\\]|\\.)*\])+\/[gimsuyx]*/g,
  // new RegExp() constructor calls
  /new\s+RegExp\s*\(\s*['"`]([^'"`]+)['"`]/g,
  // RegExp() function calls
  /RegExp\s*\(\s*['"`]([^'"`]+)['"`]/g,
  // String.match(), String.replace(), String.split() with regex
  /\.(?:match|replace|split)\s*\(\s*\/([^/]+)\/[gimsuyx]*/g
]

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
  // Look for patterns like (a+)+, (a*)*, (a+)*, etc.
  const catastrophicPatterns = [
    /\([^)]*[+*]\)[+*]/, // (something+)+ or (something*)*
    /\([^)]*\{[^}]*,\s*\}[^)]*\)[+*]/, // (something{n,})+
    /\([^)]*[+*][^)]*\)\{[^}]*,\s*\}/ // (something+){n,}
  ]

  return catastrophicPatterns.some((p) => p.test(pattern))
}

/**
 * Checks for excessive quantifiers that could lead to ReDoS
 */
function hasExcessiveQuantifiers(pattern: string): boolean {
  // Look for multiple consecutive quantifiers or high repetition counts
  const excessivePatterns = [
    /[+*?]\{[^}]*[5-9]\d+/, // Quantifiers with high repetition counts (50+)
    /[+*?][+*?]/, // Consecutive quantifiers
    /\{[^}]*,\s*\}[+*?]/ // Unbounded quantifier followed by another quantifier
  ]

  return excessivePatterns.some((p) => p.test(pattern))
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
      if (nextChar && /[+*?{]/.test(nextChar)) {
        if (hasQuantifierAtCurrentDepth) {
          return true // Found nested quantifiers
        }
      }
      depth--
    } else if (depth > 0 && char && /[+*?{]/.test(char)) {
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
  const alternationPattern = /\([^)]*\|[^)]*\)/
  const hasAlternation = alternationPattern.test(pattern)

  // Look for greedy quantifiers
  const hasGreedyQuantifiers = /[+*]\??/.test(pattern)

  // Look for word boundaries that might be exploited
  const hasPotentiallyDangerousBoundaries = /\.\*/.test(pattern)

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
      severity: 'critical',
      description: 'Pattern contains nested quantifiers that can cause catastrophic backtracking',
      recommendation:
        'Avoid nested quantifiers like (a+)+ or (a*)* that can lead to exponential time complexity'
    })
  }

  // Check for excessive quantifiers
  if (hasExcessiveQuantifiers(pattern)) {
    issues.push({
      type: 'excessive_quantifiers',
      severity: 'high',
      description: 'Pattern contains quantifiers that could lead to ReDoS attacks',
      recommendation:
        'Consider using more specific patterns or atomic groups to prevent backtracking'
    })
  }

  // Check for nested quantifiers
  if (hasNestedQuantifiers(pattern)) {
    issues.push({
      type: 'nested_quantifiers',
      severity: 'medium',
      description: 'Pattern contains nested quantifiers which can be exploited',
      recommendation:
        'Rewrite pattern to avoid nesting quantifiers inside other quantified groups'
    })
  }

  // General ReDoS vulnerability check
  if (isVulnerableToReDoS(pattern)) {
    issues.push({
      type: 'redos',
      severity: 'high',
      description:
        'Pattern is potentially vulnerable to Regular Expression Denial of Service (ReDoS)',
      recommendation:
        'Review pattern for alternation with overlapping paths and excessive quantifiers'
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
  extensions: string[] = ['**/*.{js,ts,jsx,tsx,vue}']
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
