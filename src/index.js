// index.js
const express = require("express");
const app = express();
const port = 3000;

const flow = require("./flow");
const reply = require("./reply");

app.use("/flow", flow);
app.use("/reply", reply);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
