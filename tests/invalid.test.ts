// Test file with invalid regex patterns

// Invalid regex - missing closing bracket
const invalidRegex1 = /[abc/;

// Invalid regex - unescaped special character
const invalidRegex2 = /test(/;

// Invalid regex - incomplete quantifier
const invalidRegex3 = /abc{/;

// Valid regex for comparison
const validRegex = /^[a-z]+$/;
