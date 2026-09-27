// A tainted flow in a file that has never been indexed before. The graph built
// from this directory has to be able to read it back, otherwise a first run
// reports a clean workspace.
function loadUser(req) {
  const id = req.query.id;
  return db.query('SELECT * FROM users WHERE id = ' + id);
}

module.exports = { loadUser };
