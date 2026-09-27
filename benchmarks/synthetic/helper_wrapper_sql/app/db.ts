const db = {
  async query(_sql: string) {
    return [];
  }
};

export function buildSearchQuery(term: string) {
  return `SELECT * FROM users WHERE email LIKE '%${term}%'`;
}

export async function findUsersByTerm(term: string) {
  const sql = buildSearchQuery(term);
  return db.query(sql);
}
