import mongoose from 'mongoose';

const connectDB = async () => {
  try {
    const connectionInstance = await mongoose.connect(
      `${process.env.MONGODB_URI}`
    );

    console.log(
      `\nDatabase is connected !! DB host: ${connectionInstance.connection.host} `
    );
  } catch (error) {
    console.error('Database connection failed!!');
    process.exit(1);
  }
};

export { connectDB };
