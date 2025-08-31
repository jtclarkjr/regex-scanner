import chalk from 'chalk'
import type { RegexMatch, SecurityIssue, OutputFormat } from './types'
import { HEADER_TITLE, NO_PATTERNS_FOUND, LABELS, SEVERITY_ORDER, CSV_HEADERS } from './constants'

/**
 * Formats regex scan results into the specified output format
 * @param matches Array of regex matches to format
 * @param format Output format (table, json, or csv)
 * @returns Formatted string output
 */
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

/**
 * Formats regex matches as a human-readable table with colors
 * @param matches Array of regex matches to format
 * @returns Colorized table format string
 */
function formatAsTable(matches: RegexMatch[]): string {
  if (matches.length === 0) {
    return chalk.green(NO_PATTERNS_FOUND)
  }

  const output: string[] = []

  output.push(chalk.bold.underline(HEADER_TITLE))
  output.push('')

  matches.forEach((match, index) => {
    const header = `${index + 1}. ${getValidityIndicator(match)} ${getSecurityIndicator(match)}`
    output.push(chalk.bold(header))

    output.push(`   ${chalk.dim(LABELS.pattern + ':')} ${chalk.cyan(match.pattern)}`)
    output.push(`   ${chalk.dim(LABELS.location + ':')} ${match.file}:${match.line}:${match.column}`)
    output.push(`   ${chalk.dim(LABELS.context + ':')} ${chalk.gray(match.context)}`)

    if (!match.isValid && match.validationError) {
      output.push(`   ${chalk.red(LABELS.validationError + ':')} ${match.validationError}`)
    }

    if (match.securityIssues.length > 0) {
      output.push(`   ${chalk.yellow(LABELS.securityIssues + ':')}`)
      match.securityIssues.forEach((issue, issueIndex) => {
        const severityColor = getSeverityColor(issue.severity)
        output.push(
          `      ${issueIndex + 1}. ${severityColor(issue.severity.toUpperCase())} - ${issue.type}`
        )
        output.push(`         ${issue.description}`)
        output.push(`         ${LABELS.recommendation}: ${chalk.dim(issue.recommendation)}`)
      })
    }

    output.push('') // Empty line between matches
  })

  return output.join('\n')
}

/**
 * Formats regex matches as CSV (Comma-Separated Values)
 * @param matches Array of regex matches to format
 * @returns CSV format string with headers and escaped values
 */
function formatAsCsv(matches: RegexMatch[]): string {
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

  return [CSV_HEADERS.join(','), ...rows.map((row) => row.join(','))].join('\n')
}

/**
 * Gets a colored validity indicator for a regex match
 * @param match The regex match to evaluate
 * @returns Colored string indicating SAFE, UNSAFE, or INVALID
 */
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

/**
 * Gets a colored security severity indicator for the highest severity issue
 * @param match The regex match to evaluate
 * @returns Colored string indicating highest severity level, or empty if safe
 */
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

/**
 * Gets the appropriate chalk color function for a security issue severity
 * @param severity The security issue severity level
 * @returns Chalk color function for the severity
 */
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

/**
 * Determines the highest severity level among security issues
 * @param issues Array of security issues to evaluate
 * @returns String representing the maximum severity level, or 'none' if no issues
 */
function getMaxSeverity(issues: SecurityIssue[]): string {
  if (issues.length === 0) return 'none'

  const severityOrder = SEVERITY_ORDER as readonly string[]
  let maxSeverity: string = 'low'

  for (const issue of issues) {
    if (severityOrder.indexOf(issue.severity) > severityOrder.indexOf(maxSeverity)) {
      maxSeverity = issue.severity
    }
  }

  return maxSeverity
}
