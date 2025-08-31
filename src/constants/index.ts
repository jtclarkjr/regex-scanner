import type { SecurityIssue } from '../types'

// Regex patterns used to detect regex usage in source code
export const REGEX_PATTERNS = [
  // JavaScript/TypeScript regex literals
  /\/(?![*+?])(?:[^\r\n[/\\]|\\.|\\[(?:[^\r\n\\]\\]|\\.)*\\])+\/[gimsuyx]*/g,
  // new RegExp() constructor calls
  /new\s+RegExp\s*\(\s*['"`]([^'"`]+)['"`]/g,
  // RegExp() function calls
  /RegExp\s*\(\s*['"`]([^'"`]+)['"`]/g,
  // String.match(), String.replace(), String.split() with regex
  /\.(?:match|replace|split)\s*\(\s*\/([^/]+)\/[gimsuyx]*/g
]

// Patterns that indicate catastrophic backtracking vulnerabilities
export const CATASTROPHIC_BACKTRACKING_PATTERNS = [
  /\([^)]*[+*]\)[+*]/, // (something+)+ or (something*)*
  /\([^)]*\{[^}]*,\s*\}[^)]*\)[+*]/, // (something{n,})+
  /\([^)]*[+*][^)]*\)\{[^}]*,\s*\}/ // (something+){n,}
]

// Patterns that indicate excessive quantifiers
export const EXCESSIVE_QUANTIFIER_PATTERNS = [
  /[+*?]\{[^}]*[5-9]\d+/, // Quantifiers with high repetition counts (50+)
  /[+*?][+*?]/, // Consecutive quantifiers
  /\{[^}]*,\s*\}[+*?]/ // Unbounded quantifier followed by another quantifier
]

// Pattern for detecting alternation (used in ReDoS detection)
export const ALTERNATION_PATTERN = /\([^)]*\|[^)]*\)/

// Pattern for detecting greedy quantifiers
export const GREEDY_QUANTIFIERS_PATTERN = /[+*]\??/

// Pattern for detecting potentially dangerous boundaries
export const DANGEROUS_BOUNDARIES_PATTERN = /\.\*/

// Pattern for detecting quantifier characters
export const QUANTIFIER_PATTERN = /[+*?{]/

// Security issue templates
export const SECURITY_ISSUE_TEMPLATES: Record<SecurityIssue['type'], Omit<SecurityIssue, 'type'>> = {
  catastrophic_backtracking: {
    severity: 'critical',
    description: 'Pattern contains nested quantifiers that can cause catastrophic backtracking',
    recommendation: 'Avoid nested quantifiers like (a+)+ or (a*)* that can lead to exponential time complexity'
  },
  excessive_quantifiers: {
    severity: 'high',
    description: 'Pattern contains quantifiers that could lead to ReDoS attacks',
    recommendation: 'Consider using more specific patterns or atomic groups to prevent backtracking'
  },
  nested_quantifiers: {
    severity: 'medium',
    description: 'Pattern contains nested quantifiers which can be exploited',
    recommendation: 'Rewrite pattern to avoid nesting quantifiers inside other quantified groups'
  },
  redos: {
    severity: 'high',
    description: 'Pattern is potentially vulnerable to Regular Expression Denial of Service (ReDoS)',
    recommendation: 'Review pattern for alternation with overlapping paths and excessive quantifiers'
  }
}

// Severity order for comparison
export const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'] as const

// Default file extensions to scan
export const DEFAULT_EXTENSIONS = ['**/*.{js,ts,jsx,tsx,vue}']

// App metadata and CLI defaults
export const APP_NAME = 'regex-scan'
export const APP_DESCRIPTION =
  'Security-focused regex scanner that detects, validates, and analyzes regex patterns'
export const APP_VERSION = '1.0.0'

// Common UI strings
export const HEADER_TITLE = 'Regex Security Scan Results'
export const NO_PATTERNS_FOUND = 'No regex patterns found'
export const SUMMARY_TITLE = 'Summary:'

export const LABELS = {
  pattern: 'Pattern',
  location: 'Location',
  context: 'Context',
  validationError: 'Validation Error',
  securityIssues: 'Security Issues',
  recommendation: 'Recommendation',
  file: 'File',
  line: 'Line',
  column: 'Column',
  valid: 'Valid',
  maxSeverity: 'MaxSeverity'
} as const

// CSV headers array
export const CSV_HEADERS = [
  LABELS.pattern,
  LABELS.file,
  LABELS.line,
  LABELS.column,
  LABELS.valid,
  LABELS.validationError,
  LABELS.securityIssues,
  LABELS.maxSeverity,
  LABELS.context
] as const

// CLI Messages
export const CLI_MESSAGES = {
  scanning: 'Scanning for regex patterns in:',
  pathNotExist: 'Error: Path \'%PATH%\' does not exist',
  details: 'Details:',
  noCriteriaMatches: 'No regex patterns found matching the specified criteria',
  testingPattern: 'Testing pattern:',
  valid: 'Valid:',
  yes: 'Yes',
  no: 'No',
  error: 'Error:',
  noSecurityIssues: 'No security issues detected'
} as const

// CLI Summary labels
export const SUMMARY_LABELS = {
  totalPatternsFound: 'Total patterns found:',
  invalidPatterns: 'Invalid patterns:',
  patternsWithSecurityIssues: 'Patterns with security issues:',
  criticalSecurityIssues: 'Critical security issues:',
  highSeverityIssues: 'High severity issues:'
} as const

// CLI Severity color mappings
export const SEVERITY_COLORS = {
  low: 'gray',
  medium: 'yellow', 
  high: 'red',
  critical: 'bgRed.white'
} as const
