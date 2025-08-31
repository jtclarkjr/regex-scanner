#!/usr/bin/env bun

import { Command } from 'commander'
import chalk from 'chalk'
import {
  scanDirectory,
  scanFile,
  validateRegex,
  analyzeSecurityIssues
} from './scanner.js'
import { formatResults } from './formatter.js'
import type { RegexMatch, OutputFormat } from './types'

const program = new Command()

program
  .name('regex-scan')
  .description(
    'Security-focused regex scanner that detects, validates, and analyzes regex patterns'
  )
  .version('1.0.0')

program
  .argument('[path]', 'Path to scan (file or directory)', process.cwd())
  .option('-e, --extensions <patterns...>', 'File extensions to scan', [
    '**/*.{js,ts,jsx,tsx,vue}'
  ])
  .option('-f, --format <format>', 'Output format (table, json, csv)', 'table')
  .option('--only-issues', 'Only show patterns with security issues')
  .option('--only-invalid', 'Only show invalid regex patterns')
  .option(
    '--severity <level>',
    'Minimum severity level to show (low, medium, high, critical)',
    'low'
  )
  .option('-q, --quiet', 'Suppress warnings and info messages')
  .action(
    async (
      path: string,
      options: {
        extensions: string[]
        format: OutputFormat
        onlyIssues: boolean
        onlyInvalid: boolean
        severity: 'low' | 'medium' | 'high' | 'critical'
        quiet: boolean
      }
    ) => {
      try {
        let matches: RegexMatch[]

        if (!options.quiet) {
          console.log(chalk.blue(`Scanning for regex patterns in: ${path}`))
        }

        // Check if path exists and determine if it's a file or directory
        const fs = await import('fs')

        let isDirectory = false
        try {
          const stats = fs.statSync(path)
          isDirectory = stats.isDirectory()
        } catch (error) {
          console.error(chalk.red(`Error: Path '${path}' does not exist`))
          if (error instanceof Error) {
            console.error(chalk.red(`Details: ${error.message}`))
          }
          process.exit(1)
        }

        // Scan for patterns
        if (isDirectory) {
          matches = await scanDirectory(path, options.extensions)
        } else {
          matches = scanFile(path)
        }

        // Filter results based on options
        let filteredMatches = matches

        if (options.onlyIssues) {
          filteredMatches = filteredMatches.filter((match) => match.securityIssues.length > 0)
        }

        if (options.onlyInvalid) {
          filteredMatches = filteredMatches.filter((match) => !match.isValid)
        }

        // Filter by severity
        const severityLevels = ['low', 'medium', 'high', 'critical']
        const minSeverityIndex = severityLevels.indexOf(options.severity)
        if (minSeverityIndex > 0) {
          filteredMatches = filteredMatches.filter((match) =>
            match.securityIssues.some(
              (issue) => severityLevels.indexOf(issue.severity) >= minSeverityIndex
            )
          )
        }

        // Output results
        if (filteredMatches.length === 0) {
          if (!options.quiet) {
            console.log(chalk.green('No regex patterns found matching the specified criteria'))
          }
          process.exit(0)
        }

        const output = formatResults(filteredMatches, options.format)
        console.log(output)

        // Summary statistics
        if (!options.quiet && options.format === 'table') {
          console.log('\n' + chalk.bold('Summary:'))
          console.log(`Total patterns found: ${matches.length}`)
          console.log(`Invalid patterns: ${matches.filter((m) => !m.isValid).length}`)
          console.log(
            `Patterns with security issues: ${matches.filter((m) => m.securityIssues.length > 0).length}`
          )

          const criticalIssues = matches.filter((m) =>
            m.securityIssues.some((i) => i.severity === 'critical')
          ).length
          const highIssues = matches.filter((m) =>
            m.securityIssues.some((i) => i.severity === 'high')
          ).length

          if (criticalIssues > 0) {
            console.log(chalk.red(`Critical security issues: ${criticalIssues}`))
          }
          if (highIssues > 0) {
            console.log(chalk.yellow(`High severity issues: ${highIssues}`))
          }
        }

        // Exit with error code if critical issues found
        const hasCriticalIssues = filteredMatches.some((match) =>
          match.securityIssues.some((issue) => issue.severity === 'critical')
        )

        if (hasCriticalIssues) {
          process.exit(1)
        }
      } catch (error) {
        console.error(chalk.red(`Error: ${error instanceof Error ? error.message : String(error)}`))
        process.exit(1)
      }
    }
  )

// Add a test command for quick validation
program
  .command('test-pattern')
  .description('Test a single regex pattern for validation and security issues')
  .argument('<pattern>', 'Regex pattern to test')
  .action((pattern: string) => {
    console.log(chalk.blue(`Testing pattern: ${pattern}`))
    console.log('')

    const isValid = validateRegex(pattern)
    console.log(`Valid: ${isValid ? chalk.green('Yes') : chalk.red('No')}`)

    if (!isValid) {
      try {
        new RegExp(pattern)
      } catch (error) {
        console.log(`Error: ${chalk.red(error instanceof Error ? error.message : String(error))}`)
      }
    }

    const securityIssues = analyzeSecurityIssues(pattern)
    if (securityIssues.length > 0) {
      console.log('\n' + chalk.yellow('Security Issues:'))
      securityIssues.forEach((issue, index) => {
        const severityColor = {
          low: chalk.gray,
          medium: chalk.yellow,
          high: chalk.red,
          critical: chalk.bgRed.white
        }[issue.severity]

        console.log(
          `\n${index + 1}. ${severityColor(issue.severity.toUpperCase())} - ${issue.type}`
        )
        console.log(`   ${issue.description}`)
        console.log(`   Recommendation: ${chalk.dim(issue.recommendation)}`)
      })
    } else {
      console.log('\n' + chalk.green('No security issues detected'))
    }
  })

if (import.meta.main) {
  program.parse()
}

export { program }
