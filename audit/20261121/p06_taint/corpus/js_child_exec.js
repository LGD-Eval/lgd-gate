const cp = require('child_process');
app.get('/ping', (req, res) => {
  const host = req.query.host;
  cp.exec('ping ' + host);
});
