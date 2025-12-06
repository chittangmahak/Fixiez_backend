import dotenv from 'dotenv';
dotenv.config();
import http from 'http';
import cors from 'cors';
import express from 'express';
import mongoose from 'mongoose';
import { connectDB } from './config/database.js';

const app = express();
const PORT = process.env.PORT || 5000;

// CORS
app.use(
  cors({
    origin: ['http://localhost:5173', 'http://localhost:5174'],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'],
    credentials: true,
  })
);

app.use(express.json());

// HTTP + WebSocket Server
const server = http.createServer(app);

connectDB()
  .then(() => {
    console.log('✅ MongoDB connected successfully');
  })
  .catch((err) => {
    console.error('❌ MongoDB connection error');
  });

// Start Express server
server.listen(PORT, () => {
  console.log(`🚀 Local server running on http://localhost:${PORT}`);
});
