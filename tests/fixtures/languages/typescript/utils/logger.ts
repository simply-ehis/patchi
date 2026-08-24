export function log(message: string): void {
  console.log(`[APP] ${message}`);
}

export function error(message: string): void {
  console.error(`[ERROR] ${message}`);
}

const unusedHelper = (x: any) => x;
