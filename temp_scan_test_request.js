(async () => {
  try {
    const res = await fetch('http://localhost:5000/api/scan/code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: '<?php if (isset($_GET["ip"])) { system("ping -c 3 " . $_GET["ip"]); } ?>',
        filename: 'test.php'
      })
    });
    const json = await res.json();
    console.log(JSON.stringify(json, null, 2));
  } catch (err) {
    console.error(err);
  }
})();
