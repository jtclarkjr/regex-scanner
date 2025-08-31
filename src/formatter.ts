import chalk from 'chalk'
import type { RegexMatch, SecurityIssue, OutputFormat } from './types'

export function formatResults(matches: RegexMatch[], format: OutputFormat): string {
  switch (format) {
    case 'json':
      return JSON.stringify(matches, null, 2)
    case 'csv':
      return formatAsCsv(matches)
    case 'table':
    default:
      return formatAsTable(matches)
  }
}

function formatAsTable(matches: RegexMatch[]): string {
  if (matches.length === 0) {
    return chalk.green('No regex patterns found')
  }

  const output: string[] = []

  output.push(chalk.bold.underline('Regex Security Scan Results'))
  output.push('')

  matches.forEach((match, index) => {
    const header = `${index + 1}. ${getValidityIndicator(match)} ${getSecurityIndicator(match)}`
    output.push(chalk.bold(header))

    output.push(`   ${chalk.dim('Pattern:')} ${chalk.cyan(match.pattern)}`)
    output.push(`   ${chalk.dim('Location:')} ${match.file}:${match.line}:${match.column}`)
    output.push(`   ${chalk.dim('Context:')} ${chalk.gray(match.context)}`)

    if (!match.isValid && match.validationError) {
      output.push(`   ${chalk.red('Validation Error:')} ${match.validationError}`)
    }

    if (match.securityIssues.length > 0) {
      output.push(`   ${chalk.yellow('Security Issues:')}`)
      match.securityIssues.forEach((issue, issueIndex) => {
        const severityColor = getSeverityColor(issue.severity)
        output.push(
          `      ${issueIndex + 1}. ${severityColor(issue.severity.toUpperCase())} - ${issue.type}`
        )
        output.push(`         ${issue.description}`)
        output.push(`         Recommendation: ${chalk.dim(issue.recommendation)}`)
      })
    }

    output.push('') // Empty line between matches
  })

  return output.join('\n')
}

function formatAsCsv(matches: RegexMatch[]): string {
  const headers = [
    'Pattern',
    'File',
    'Line',
    'Column',
    'Valid',
    'ValidationError',
    'SecurityIssues',
    'MaxSeverity',
    'Context'
  ]

  const rows = matches.map((match) => [
    `"${match.pattern.replace(/"/g, '""')}"`,
    `"${match.file}"`,
    match.line.toString(),
    match.column.toString(),
    match.isValid.toString(),
    `"${(match.validationError || '').replace(/"/g, '""')}"`,
    match.securityIssues.length.toString(),
    getMaxSeverity(match.securityIssues),
    `"${match.context.replace(/"/g, '""')}"`
  ])

  return [headers.join(','), ...rows.map((row) => row.join(','))].join('\n')
}

function getValidityIndicator(match: RegexMatch): string {
  if (!match.isValid) {
    return chalk.red('INVALID')
  }
  
  // If valid but has security issues, show warning instead of checkmark
  if (match.securityIssues.length > 0) {
    return chalk.yellow('UNSAFE')
  }
  
  // Only show green checkmark if valid AND no security issues
  return chalk.green('SAFE')
}

function getSecurityIndicator(match: RegexMatch): string {
  if (match.securityIssues.length === 0) {
    return '' // No additional indicator needed when safe
  }

  const maxSeverity = getMaxSeverity(match.securityIssues)
  switch (maxSeverity) {
    case 'critical':
      return chalk.bgRed.white('CRITICAL')
    case 'high':
      return chalk.red('HIGH')
    case 'medium':
      return chalk.yellow('MEDIUM')
    case 'low':
    default:
      return chalk.gray('LOW')
  }
}

function getSeverityColor(severity: SecurityIssue['severity']) {
  switch (severity) {
    case 'critical':
      return chalk.bgRed.white
    case 'high':
      return chalk.red
    case 'medium':
      return chalk.yellow
    case 'low':
    default:
      return chalk.gray
  }
}

function getMaxSeverity(issues: SecurityIssue[]): string {
  if (issues.length === 0) return 'none'

  const severityOrder = ['low', 'medium', 'high', 'critical']
  let maxSeverity = 'low'

  for (const issue of issues) {
    if (severityOrder.indexOf(issue.severity) > severityOrder.indexOf(maxSeverity)) {
      maxSeverity = issue.severity
    }
  }

  return maxSeverity
}
