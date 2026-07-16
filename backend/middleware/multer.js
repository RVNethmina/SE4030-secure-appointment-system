import multer from 'multer'
import crypto from 'crypto'
import path from 'path'
import fs from 'fs'

// Ensure a dedicated upload directory exists (instead of writing to CWD).
const uploadDir = 'uploads'
fs.mkdirSync(uploadDir, { recursive: true })

// Only allow real image types; reject anything else (e.g. .php, .html, .svg).
const ALLOWED_MIME = new Set(['image/jpeg', 'image/png', 'image/webp'])
const ALLOWED_EXT = new Set(['.jpg', '.jpeg', '.png', '.webp'])

const storage = multer.diskStorage({
  destination: function (req, file, callback) {
    callback(null, uploadDir)
  },
  filename: function (req, file, callback) {
    // Generate a random, extension-controlled name. The original used
    // file.originalname verbatim, allowing path traversal (e.g. "../../x")
    // and overwriting of arbitrary files (CWE-22 / CWE-434).
    const ext = path.extname(file.originalname).toLowerCase()
    const safeExt = ALLOWED_EXT.has(ext) ? ext : '.jpg'
    const randomName = crypto.randomBytes(16).toString('hex') + safeExt
    callback(null, randomName)
  },
})

const fileFilter = (req, file, callback) => {
  const ext = path.extname(file.originalname).toLowerCase()
  if (ALLOWED_MIME.has(file.mimetype) && ALLOWED_EXT.has(ext)) {
    return callback(null, true)
  }
  callback(new Error('Only JPEG, PNG or WEBP image files are allowed.'))
}

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 2 * 1024 * 1024, // 2 MB cap (was unlimited)
    files: 1,
  },
})

export default upload
