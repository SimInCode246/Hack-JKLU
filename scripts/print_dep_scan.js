(async () => {
  const base = 'http://localhost:5000';
  const pkg = { name: 'test', version: '1.0.0', dependencies: { lodash: '4.17.20' } };

  const res = await fetch(base + '/api/scan/dependencies', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ packageJson: JSON.stringify(pkg, null, 2) })
  });
  const data = await res.json();
  console.log('status', res.status);
  console.log('result', JSON.stringify(data, null, 2));
})();
