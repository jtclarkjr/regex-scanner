// Test file with various regex patterns

// Valid and safe regex patterns
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const phoneRegex = /^\+?[\d\s()-]{10,}$/;

// Invalid regex pattern (missing closing bracket)
const invalidRegex = /[abc/;

// Potentially dangerous regex patterns (ReDoS vulnerabilities)
const vulnerableRegex1 = /(a+)+b/; // Catastrophic backtracking
const vulnerableRegex2 = /(a|a)*b/; // Alternation with overlapping matches
const vulnerableRegex3 = /^(a+)+$/; // Nested quantifiers

// Constructor patterns
const constructorRegex = new RegExp('(x+)+y');
const functionRegex = RegExp('(\\\\d+)*\\\\d');

// String method usage
const str = 'test';
str.match(/(a*)*/);
str.replace(/(b+)+/, 'replacement');

console.log('Testing regex patterns...');
