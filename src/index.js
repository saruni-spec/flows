// index.js
const express = require("express");
const app = express();
const port = 3000;

const flow = require("./flow");

app.use("/flow", flow);

app.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});
