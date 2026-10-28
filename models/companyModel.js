const db = require("../config/db");

const listActive = async () => {
    const [rows] = await db.execute(
        `SELECT id, name
         FROM companies
         WHERE status = 1
         ORDER BY name ASC`
    );

    return rows;
};

const findActiveById = async (id) => {
    const [rows] = await db.execute(
        `SELECT id, name, status
         FROM companies
         WHERE id = ? AND status = 1
         LIMIT 1`,
        [id]
    );

    return rows[0] || null;
};

module.exports = {
    listActive,
    findActiveById
};
