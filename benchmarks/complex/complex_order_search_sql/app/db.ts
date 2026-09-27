export const db = {
  async query(sql: string) {
    return [{ sql }];
  }
};
