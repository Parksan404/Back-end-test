const mongoose = require('mongoose');
const { MONGO_URI } = process.env;

exports.connect = () => {
    mongoose.connect(MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    })
    .then(() => {
        console.log("Successfully connected to database");
    })
    .catch((error) => {
        console.error("Database connection error:", error);
    });
};
