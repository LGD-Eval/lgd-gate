app.get('/mod', (req, res) => {
  const name = req.query.name;
  require(name);
});
