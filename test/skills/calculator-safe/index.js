/**
 * Calculator Skill — Simple arithmetic for OpenClaw
 * A known-safe skill with no risky patterns.
 */

function add(a, b) { return a + b; }
function subtract(a, b) { return a - b; }
function multiply(a, b) { return a * b; }
function divide(a, b) {
  if (b === 0) throw new Error('Division by zero');
  return a / b;
}

function calculate(expression) {
  const ops = { '+': add, '-': subtract, '*': multiply, '/': divide };
  // Simple two-operand parser
  for (const [sym, fn] of Object.entries(ops)) {
    const idx = expression.lastIndexOf(sym);
    if (idx > 0) {
      const left = parseFloat(expression.slice(0, idx).trim());
      const right = parseFloat(expression.slice(idx + 1).trim());
      if (!isNaN(left) && !isNaN(right)) {
        return fn(left, right);
      }
    }
  }
  return parseFloat(expression) || 0;
}

module.exports = {
  name: 'Calculator',
  version: '1.0.0',
  description: 'Simple arithmetic calculations',
  actions: {
    calculate: {
      description: 'Evaluate a math expression',
      handler: (params) => ({ result: calculate(params.expression) }),
    },
  },
};
