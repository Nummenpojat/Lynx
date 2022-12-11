require("dotenv").config("../../../.env");
const express = require("express");
const mongoSanitize = require("express-mongo-sanitize");
const bodyParser = require("body-parser");
const createURL = require("./db/modules/url/create");
const listURL = require("./db/modules/url/list");

const mongoose = require("mongoose");
const setup = require("./modules/setup");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(mongoSanitize({ allowDots: true }));

app.use("/api", require("./api"));

const mongoDB = `mongodb://${process.env.DB_USER}:${encodeURIComponent(process.env.DB_PASSWORD)}@${process.env.DB_HOST}:${
	process.env.DB_PORT
}/shortener?authSource=admin`;

mongoose.set("strictQuery", false);

mongoose.connect(
	mongoDB,
	{
		useNewUrlParser: true,
		useUnifiedTopology: true,
	},
	() => {
		console.log("Connected to DB!");
	}
);

const db = mongoose.connection;

db.on("error", console.error.bind(console, "MongoDB connection error:"));

const listenPort = process.env.EXPRESS_PORT || 3000;
setup().then(() => {
	app.listen(listenPort, async () => {
		console.log(`Listening on port ${listenPort}`);
		createURL({ destination: "https://stackoverflow.com/questions/5062614/how-to-decide-when-to-use-node-js?rq=1", author: "1234" });
		listURL({
			pagesize: 50,
			page: 0,
		});
	});
});
