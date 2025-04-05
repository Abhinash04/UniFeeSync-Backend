import express, { json } from 'express';
import cors from 'cors';
import morgan from 'morgan';
import { config } from 'dotenv';
import connectDB from './config/db.js';

// Load environment variables
config();

// Connect to MongoDB
connectDB();

// Initialize Express
const app = express();

// Middleware
app.use(json());
app.use(cors());
app.use(morgan('dev'));

// Routes (use full paths + .js when using ES Modules)
import authRoutes from './routes/auth.js';
import studentRoutes from './routes/student.js';
import adminRoutes from './routes/admin.js';
import paymentRoutes from './routes/payment.js';

app.use('/api/auth', authRoutes);
app.use('/api/student', studentRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/payment', paymentRoutes);

// Error handler middleware
import errorHandler from './middleware/errorHandler.js';
app.use(errorHandler);

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});