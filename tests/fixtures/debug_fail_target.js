// Intentionally buggy JavaScript target for debug capture verification

function processOrder(items) {
    // BUG: items is null, accessing .total will throw
    const total = items.total;
    return total + 5;
}

function helper() {
    const multiplier = 2;
    return multiplier;
}

helper();  // Run helper to generate stack frames
const result = processOrder(null);  // Pass null to trigger TypeError
console.log(result);  // This won't be reached