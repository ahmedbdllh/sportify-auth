const mongoose = require('mongoose');
require('dotenv').config({ path: '../.env' }); // Adjust path if .env is in root of backend

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      // Mongoose 6 no longer supports useCreateIndex and useFindAndModify
      // useCreateIndex: true, 
      // useFindAndModify: false,
    });

    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`Error connecting to MongoDB: ${error.message}`);
    process.exit(1); // Exit process with failure
  }
};

module.exports = connectDB;