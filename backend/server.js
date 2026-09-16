import express from 'express'
import multer from 'multer'
import cors from 'cors'
import helmet from 'helmet'
import mongoSanitize from 'express-mongo-sanitize'
import 'dotenv/config'
import connectDB from './config/mongodb.js'
import connectCloudinary from './config/cloudinary.js'
import adminRouter from './routes/adminRoute.js'
import doctorRouter from './routes/doctorRoute.js'
import useRouter from './routes/userRoutes.js'
import { assertJwtSecret } from './utils/token.js'
import { assertAdminCredentials } from './controllers/adminController.js'
import { apiLimiter } from './middleware/rateLimiter.js'

// Fail fast at boot if the JWT signing secret is missing or weak, instead of
// silently issuing forgeable tokens (the original shipped JWT_SECRET='RBRO').
assertJwtSecret()
// Same for the bootstrap admin credential (the original was 'qwerty123').
assertAdminCredentials()

//app config
const app = express()
const port = process.env.PORT || 4000
connectDB()
connectCloudinary()

// Only trust X-Forwarded-For when the API really sits behind a reverse proxy.
// Trusting it unconditionally let any client pick its own "IP" per request
// and walk straight past the login rate limiter (CWE-348). Set TRUST_PROXY to
// the number of proxy hops (e.g. 1) in production behind a load balancer.
const trustProxy = process.env.TRUST_PROXY
if (trustProxy) {
  app.set('trust proxy', /^\d+$/.test(trustProxy) ? Number(trustProxy) : trustProxy)
}

//middlewares
// Cap request body size to blunt large-payload DoS (was unlimited).
app.use(express.json({ limit: '1mb' }))
app.use(express.urlencoded({ extended: true, limit: '1mb' }))

// Security headers (CSP, HSTS, X-Content-Type-Options, frame-guard, etc.).
app.use(helmet())

// Strip any keys containing '$' or '.' from req.body/query/params so attackers
// cannot inject MongoDB query operators such as { "$ne": null } (CWE-943).
app.use(mongoSanitize())

// Restrict CORS to an explicit allow-list of origins instead of '*'.
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:5173,http://localhost:5174')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean)

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow non-browser tools (no Origin header) and any allow-listed origin.
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true)
      }
      return callback(new Error('Not allowed by CORS'))
    },
    credentials: true,
  })
)

// Global rate-limit backstop for the whole API.
app.use('/api', apiLimiter)

//api endpoints
app.use('/api/admin', adminRouter)
app.use('/api/doctor', doctorRouter)
app.use('/api/user/', useRouter)

app.get('/', (req, res) => {
  res.send('API WORKING great')
})

// Central error handler: log server-side, return a generic message so internal
// details / stack traces are never leaked to clients (CWE-209).
app.use((err, req, res, next) => {
  if (err && err.message === 'Not allowed by CORS') {
    return res.status(403).json({ success: false, message: 'Origin not allowed.' })
  }
  // Upload validation problems (size/count limits, disallowed type) are client
  // errors with safe, generic messages: report them as 400, not 500.
  if (err instanceof multer.MulterError || err?.expose) {
    return res.status(err.status || 400).json({ success: false, message: err.message })
  }
  console.error('[unhandled error]', err?.message)
  res.status(500).json({ success: false, message: 'Internal server error.' })
})

//start express app
app.listen(port, () => console.log("Server Started", port))
