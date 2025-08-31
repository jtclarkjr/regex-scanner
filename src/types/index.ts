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

export type OutputFormat = 'table' | 'json' | 'csv'
