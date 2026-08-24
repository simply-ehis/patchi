export function neverCalled(): number {
  return 42;
}

export const unusedConstant: string = "I am never referenced";

export class UnusedClass {
  method(): void {}
}
