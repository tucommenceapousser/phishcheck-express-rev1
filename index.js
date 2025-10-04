require('dotenv').config();
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const xssClean = require('xss-clean');
const { createServer } = require('http');
const { Server } = require('socket.io');

const analyzeRouter = require('./routes/analyze');

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: process.env.CORS_ORIGIN || '*', // tighten in production
    methods: ['GET','POST']
  }
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use('/public', express.static(path.join(__dirname, 'public')));

// Security headers
app.use(helmet());
// CORS - configure origins in env for production
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
// Prevent basic XSS injections on body
app.use(xssClean());

// Basic rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests, slow down.'
});
app.use(limiter);

// simple socket.io usage: emit progress events for long running scans
io.on('connection', (socket) => {
  console.log('socket connected', socket.id);
  socket.on('hello', (msg) => socket.emit('reply', `hi ${socket.id}`));
});

app.get('/', (req, res) => res.render('index'));
app.use('/analyze', analyzeRouter);

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => console.log(`Server listening on ${PORT}`));
