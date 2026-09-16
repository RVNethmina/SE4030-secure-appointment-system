// Load .env before any module that reads process.env at import time.
import 'dotenv/config'
import app from './app.js'
import connectDB from './config/mongodb.js'
import connectCloudinary from './config/cloudinary.js'
import { assertJwtSecret } from './utils/token.js'
import { assertAdminCredentials } from './controllers/adminController.js'

// Fail fast at boot if the JWT signing secret is missing or weak, instead of
// silently issuing forgeable tokens (the original shipped JWT_SECRET='RBRO').
assertJwtSecret()
// Same for the bootstrap admin credential (the original was 'qwerty123').
assertAdminCredentials()

const port = process.env.PORT || 4000
connectDB()
connectCloudinary()

//start express app
app.listen(port, () => console.log("Server Started", port))
