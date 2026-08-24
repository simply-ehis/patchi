function neverCalled() {
  return 42;
}

const unusedConstant = "I am never referenced";

module.exports = { neverCalled, unusedConstant };
