#!/usr/bin/env bun

import { Command } from 'commander'
import chalk from 'chalk'
import {
  scanDirectory,
  scanFile,
  validateRegex,
  analyzeSecurityIssues
} from './scanner'
import { formatResults } from './formatter'
import type { RegexMatch, OutputFormat } from './types'
import {
  APP_NAME,
  APP_DESCRIPTION,
  APP_VERSION,
  DEFAULT_EXTENSIONS,
  SEVERITY_ORDER,
  CLI_MESSAGES,
  SUMMARY_TITLE,
  SUMMARY_LABELS,
  LABELS
} from './constants/index.js'

const program = new Command()

program
  .name(APP_NAME)
  .description(APP_DESCRIPTION)
  .version(APP_VERSION)

program
  .argument('[path]', 'Path to scan (file or directory)', process.cwd())
  .option('-e, --extensions <patterns...>', 'File extensions to scan', DEFAULT_EXTENSIONS)
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
          console.log(chalk.blue(`${CLI_MESSAGES.scanning} ${path}`))
        }

        // Check if path exists and determine if it's a file or directory
        const fs = await import('fs')

        let isDirectory = false
        try {
          const stats = fs.statSync(path)
          isDirectory = stats.isDirectory()
        } catch (error) {
          console.error(chalk.red(CLI_MESSAGES.pathNotExist.replace('%PATH%', path)))
          if (error instanceof Error) {
            console.error(chalk.red(`${CLI_MESSAGES.details} ${error.message}`))
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
        const severityLevels = SEVERITY_ORDER as readonly string[]
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
            console.log(chalk.green(CLI_MESSAGES.noCriteriaMatches))
          }
          process.exit(0)
        }

        const output = formatResults(filteredMatches, options.format)
        console.log(output)

        // Summary statistics
        if (!options.quiet && options.format === 'table') {
          console.log('\n' + chalk.bold(SUMMARY_TITLE))
          console.log(`${SUMMARY_LABELS.totalPatternsFound} ${matches.length}`)
          console.log(`${SUMMARY_LABELS.invalidPatterns} ${matches.filter((m) => !m.isValid).length}`)
          console.log(
            `${SUMMARY_LABELS.patternsWithSecurityIssues} ${matches.filter((m) => m.securityIssues.length > 0).length}`
          )

          const criticalIssues = matches.filter((m) =>
            m.securityIssues.some((i) => i.severity === 'critical')
          ).length
          const highIssues = matches.filter((m) =>
            m.securityIssues.some((i) => i.severity === 'high')
          ).length

          if (criticalIssues > 0) {
            console.log(chalk.red(`${SUMMARY_LABELS.criticalSecurityIssues} ${criticalIssues}`))
          }
          if (highIssues > 0) {
            console.log(chalk.yellow(`${SUMMARY_LABELS.highSeverityIssues} ${highIssues}`))
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
        console.error(chalk.red(`${CLI_MESSAGES.error} ${error instanceof Error ? error.message : String(error)}`))
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
    console.log(chalk.blue(`${CLI_MESSAGES.testingPattern} ${pattern}`))
    console.log('')

    const isValid = validateRegex(pattern)
    console.log(`${CLI_MESSAGES.valid} ${isValid ? chalk.green(CLI_MESSAGES.yes) : chalk.red(CLI_MESSAGES.no)}`)

    if (!isValid) {
      try {
        new RegExp(pattern)
      } catch (error) {
        console.log(`${CLI_MESSAGES.error} ${chalk.red(error instanceof Error ? error.message : String(error))}`)
      }
    }

    const securityIssues = analyzeSecurityIssues(pattern)
    if (securityIssues.length > 0) {
      console.log('\n' + chalk.yellow(`${LABELS.securityIssues}:`))
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
        console.log(`   ${LABELS.recommendation}: ${chalk.dim(issue.recommendation)}`)
      })
    } else {
      console.log('\n' + chalk.green(CLI_MESSAGES.noSecurityIssues))
    }
  })

if (import.meta.main) {
  program.parse()
}

export { program }
