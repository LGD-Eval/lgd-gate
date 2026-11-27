router.post('/run', (req, res) => {
  const code = req.body.code;
  eval(code);
});
