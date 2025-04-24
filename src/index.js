// index.js
const express = require("express");
const app = express();
const port = 3000;

const flow = require("./flow");

app.use("/flow", flow);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
