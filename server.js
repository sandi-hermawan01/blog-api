import express from "express";

const server = express();
const PORT = process.env.PORT || 3003;

// middlewares
server.use(express.json()); // enable JSON sharing

server.get("/", (req, res) => {
  res.json("Welcome, this is Home Api");
});

server.listen(PORT, () => {
  console.log("listening on port -> " + PORT);
});
