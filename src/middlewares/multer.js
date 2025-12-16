import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const UPLOAD_BASE = path.join(__dirname, '..', 'uploads');

const storaage = multer.diskStorage({
  destination: (req, file, cb) => {
    try {
      // const userId = req.user?.id;
      // fileType = req.uploadType;

      // if (!userId) {
      //   return cb(new Error('User not authenticated'), null);
      // }
      // if (!fileType) {
      //   return cb(new Error('fileType or category missing'), null);
      // }

      const uploadPath = path.join(UPLOAD_BASE);

      fs.mkdirSync(uploadPath, { recursive: true });
      cb(null, uploadPath);
    } catch (error) {
      cb(error, null);
    }
  },

  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  },
});

const allowedFileTypes = [
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
];

const fileFilter = (req, file, cb) => {
  if (allowedFileTypes.includes(file.mimetype)) cb(null, true);
  else
    cb(
      new Error('Unsupported file type!! Only pdf , doc and docx are allowed '),
      false
    );
};

export const uploader = multer({
  storage: storaage,
  fileFilter: fileFilter,
  limits: { fileSize: 5 * 1024 * 1024, files: 10 },
});
