const winston = require("winston");
const path = require("path");

const logDirectory = path.join(__dirname, "../logs");

const logger = winston.createLogger({
  level: "info", // Log only if severity is "info" or higher
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level.toUpperCase()}]: ${message}`;
    })
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(logDirectory, "errors.log"),
      level: "error",
    }),
    new winston.transports.File({
      filename: path.join(logDirectory, "requests.log"),
    }),
    new winston.transports.Console(),
  ],
});

module.exports = logger;
