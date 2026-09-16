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

// Errors raised while validating an upload are safe to show to the client.
const uploadError = (message) => {
  const err = new Error(message)
  err.status = 400
  err.expose = true
  return err
}

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
  callback(uploadError('Only JPEG, PNG or WEBP image files are allowed.'))
}

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 2 * 1024 * 1024, // 2 MB cap (was unlimited)
    files: 1,
  },
})

// Delete a temporary upload from local disk. Files are pushed to Cloudinary,
// so keeping the local copy only lets repeated uploads fill the disk.
export const removeUploadedFile = async (file) => {
  if (!file?.path) return
  await fs.promises.unlink(file.path).catch(() => {})
}

// Magic-byte signatures of the allowed formats.
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
const isJpeg = (b) => b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff
const isPng = (b) => b.length >= 8 && b.subarray(0, 8).equals(PNG_SIGNATURE)
const isWebp = (b) =>
  b.length >= 12 &&
  b.subarray(0, 4).toString('ascii') === 'RIFF' &&
  b.subarray(8, 12).toString('ascii') === 'WEBP'

/**
 * The MIME type and extension checked by fileFilter are both supplied by the
 * client and trivially spoofed. After multer has stored the file, read its
 * first bytes and reject (and delete) anything that is not really an image.
 */
export const verifyImageSignature = async (req, res, next) => {
  if (!req.file) return next()

  let header = Buffer.alloc(0)
  try {
    const handle = await fs.promises.open(req.file.path, 'r')
    try {
      const { bytesRead, buffer } = await handle.read(Buffer.alloc(12), 0, 12, 0)
      header = buffer.subarray(0, bytesRead)
    } finally {
      await handle.close()
    }
  } catch {
    // unreadable file: fall through to the rejection below
  }

  if (isJpeg(header) || isPng(header) || isWebp(header)) return next()

  await removeUploadedFile(req.file)
  return res
    .status(400)
    .json({ success: false, message: 'Uploaded file is not a valid image.' })
}

export default upload
