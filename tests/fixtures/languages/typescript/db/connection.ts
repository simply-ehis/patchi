export const db = {
  query(sql: string, params?: any[]): any[] {
    return [];
  },
  insert(table: string, data: any): any {
    return data;
  },
  update(table: string, id: number, data: any): any {
    return data;
  },
  delete(table: string, id: number): boolean {
    return true;
  },
};
