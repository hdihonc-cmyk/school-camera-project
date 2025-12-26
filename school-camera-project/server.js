// ============================================
// SCHOOL CAMERA PROJECT - SERVER
// Educational Purposes Only
// ============================================

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
require('dotenv').config();

// Initialize Express
const app = express();
const PORT = process.env.PORT || 3000;

// ========== CONFIGURATION ==========
const CONFIG = {
    // Security
    teacherToken: process.env.TEACHER_TOKEN || 'default-school-token-' + Date.now(),
    
    // File upload
    uploadDir: 'uploads',
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 50 * 1024 * 1024, // 50MB
    allowedTypes: (process.env.ALLOWED_TYPES || 'image/jpeg,image/png,image/gif,video/webm,video/mp4').split(','),
    
    // Server
    domain: process.env.DOMAIN || `http://localhost:${PORT}`,
    sessionSecret: process.env.SESSION_SECRET || 'school-project-secret'
};

// ========== SETUP ==========
// Ensure directories exist
if (!fs.existsSync(CONFIG.uploadDir)) {
    fs.mkdirSync(CONFIG.uploadDir, { recursive: true });
}

// Create logs directory
if (!fs.existsSync('logs')) {
    fs.mkdirSync('logs', { recursive: true });
}

// ========== MIDDLEWARE ==========
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Logging middleware
app.use((req, res, next) => {
    const logEntry = {
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent')
    };
    
    fs.appendFileSync(
        'logs/access.log',
        JSON.stringify(logEntry) + '\n'
    );
    
    next();
});

// ========== FILE UPLOAD CONFIGURATION ==========
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        // Create folder based on session/user ID
        const sessionId = req.body.sessionId || req.headers['x-session-id'] || 'anonymous';
        const userDir = path.join(CONFIG.uploadDir, sessionId);
        
        if (!fs.existsSync(userDir)) {
            fs.mkdirSync(userDir, { recursive: true });
        }
        
        cb(null, userDir);
    },
    filename: (req, file, cb) => {
        // Create safe filename with timestamp
        const timestamp = Date.now();
        const random = Math.random().toString(36).substring(7);
        const originalName = file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
        const extension = path.extname(originalName);
        const name = path.basename(originalName, extension);
        
        cb(null, `${name}-${timestamp}-${random}${extension}`);
    }
});

const fileFilter = (req, file, cb) => {
    if (CONFIG.allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error(`File type ${file.mimetype} not allowed. Only ${CONFIG.allowedTypes.join(', ')} are supported.`), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: CONFIG.maxFileSize,
        files: 1
    }
});

// ========== AUTHENTICATION ==========
// Simple token-based authentication for teacher
const authenticateTeacher = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            error: 'Authentication required',
            message: 'Please provide a valid teacher token'
        });
    }
    
    const token = authHeader.slice(7);
    
    if (token === CONFIG.teacherToken) {
        next();
    } else {
        res.status(403).json({
            error: 'Access denied',
            message: 'Invalid teacher token'
        });
    }
};

// ========== ROUTES ==========

// 1. Home Page - Student Interface
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 2. Teacher Dashboard
app.get('/teacher', authenticateTeacher, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'teacher.html'));
});

// 3. Get Server Info (for teacher)
app.get('/api/info', authenticateTeacher, (req, res) => {
    const info = {
        server: {
            version: '1.0.0',
            uptime: process.uptime(),
            nodeVersion: process.version,
            platform: process.platform,
            memory: process.memoryUsage()
        },
        config: {
            uploadDir: CONFIG.uploadDir,
            maxFileSize: CONFIG.maxFileSize,
            allowedTypes: CONFIG.allowedTypes,
            domain: CONFIG.domain
        },
        stats: getStorageStats()
    };
    
    res.json(info);
});

// 4. Upload File (Student submits media)
app.post('/api/upload', upload.single('media'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                error: 'No file uploaded',
                message: 'Please select a photo or video to upload'
            });
        }
        
        // Validate required fields
        if (!req.body.consent || req.body.consent !== 'true') {
            // Delete the uploaded file if consent not given
            fs.unlinkSync(req.file.path);
            return res.status(400).json({
                error: 'Consent required',
                message: 'You must agree to the terms before uploading'
            });
        }
        
        // Create metadata object
        const metadata = {
            id: Date.now() + '-' + Math.random().toString(36).substr(2, 9),
            filename: req.file.filename,
            originalName: req.file.originalname,
            mimetype: req.file.mimetype,
            size: req.file.size,
            path: req.file.path,
            destination: req.file.destination,
            sessionId: req.body.sessionId || 'unknown',
            userId: req.body.userId || 'anonymous',
            consent: req.body.consent === 'true',
            purpose: req.body.purpose || 'school_project',
            timestamp: new Date().toISOString(),
            ip: req.ip || req.connection.remoteAddress
        };
        
        // Save metadata
        const metadataPath = path.join(req.file.destination, req.file.filename + '.json');
        fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));
        
        // Log the upload
        const uploadLog = {
            action: 'upload',
            ...metadata,
            serverTime: new Date().toISOString()
        };
        
        fs.appendFileSync(
            'logs/uploads.log',
            JSON.stringify(uploadLog) + '\n'
        );
        
        // Return success response
        res.json({
            success: true,
            message: 'File uploaded successfully for educational purposes',
            file: {
                id: metadata.id,
                filename: metadata.filename,
                size: metadata.size,
                type: metadata.mimetype,
                url: `/uploads/${metadata.sessionId}/${metadata.filename}`,
                downloadUrl: `/api/download/${metadata.sessionId}/${metadata.filename}`,
                timestamp: metadata.timestamp
            },
            notice: 'This file is stored for educational evaluation only and will be deleted after project assessment.'
        });
        
    } catch (error) {
        console.error('Upload error:', error);
        
        // Clean up file if there was an error
        if (req.file && req.file.path && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        
        res.status(500).json({
            error: 'Upload failed',
            message: error.message || 'An error occurred during upload'
        });
    }
});

// 5. Download File (Teacher access)
app.get('/api/download/:sessionId/:filename', authenticateTeacher, (req, res) => {
    const filePath = path.join(CONFIG.uploadDir, req.params.sessionId, req.params.filename);
    
    if (fs.existsSync(filePath)) {
        res.download(filePath, err => {
            if (err) {
                console.error('Download error:', err);
                res.status(500).json({ error: 'Download failed' });
            }
        });
    } else {
        res.status(404).json({ error: 'File not found' });
    }
});

// 6. List All Uploads (Teacher access)
app.get('/api/uploads', authenticateTeacher, (req, res) => {
    try {
        const uploads = [];
        
        function scanDirectory(dir, basePath = '') {
            if (!fs.existsSync(dir)) return;
            
            const items = fs.readdirSync(dir, { withFileTypes: true });
            
            items.forEach(item => {
                const fullPath = path.join(dir, item.name);
                const relativePath = path.join(basePath, item.name);
                
                if (item.isDirectory()) {
                    scanDirectory(fullPath, relativePath);
                } else if (item.isFile() && !item.name.endsWith('.json')) {
                    // Skip metadata files for this list
                    const metadataPath = fullPath + '.json';
                    let metadata = {};
                    
                    if (fs.existsSync(metadataPath)) {
                        try {
                            metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
                        } catch (e) {
                            console.error('Error reading metadata:', e);
                        }
                    }
                    
                    const stat = fs.statSync(fullPath);
                    
                    uploads.push({
                        id: metadata.id || path.basename(item.name, path.extname(item.name)),
                        filename: item.name,
                        path: relativePath,
                        fullPath: fullPath,
                        url: `/uploads/${relativePath}`,
                        downloadUrl: `/api/download/${relativePath}`,
                        size: stat.size,
                        formattedSize: formatBytes(stat.size),
                        created: stat.birthtime,
                        modified: stat.mtime,
                        type: path.extname(item.name).substring(1).toLowerCase(),
                        mimetype: getMimeType(item.name),
                        metadata: metadata,
                        sessionId: relativePath.split('/')[0],
                        userId: metadata.userId || 'unknown',
                        consentGiven: metadata.consent || false,
                        purpose: metadata.purpose || 'unknown'
                    });
                }
            });
        }
        
        scanDirectory(CONFIG.uploadDir);
        
        // Sort by date (newest first)
        uploads.sort((a, b) => new Date(b.created) - new Date(a.created));
        
        res.json({
            success: true,
            count: uploads.length,
            totalSize: formatBytes(uploads.reduce((sum, file) => sum + file.size, 0)),
            uploads: uploads
        });
        
    } catch (error) {
        console.error('Error listing uploads:', error);
        res.status(500).json({
            error: 'Failed to list uploads',
            message: error.message
        });
    }
});

// 7. Delete File (Teacher access)
app.delete('/api/upload/:sessionId/:filename', authenticateTeacher, (req, res) => {
    const filePath = path.join(CONFIG.uploadDir, req.params.sessionId, req.params.filename);
    const metadataPath = filePath + '.json';
    
    try {
        let deletedFiles = [];
        
        // Delete main file
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
            deletedFiles.push(req.params.filename);
        }
        
        // Delete metadata file
        if (fs.existsSync(metadataPath)) {
            fs.unlinkSync(metadataPath);
            deletedFiles.push(req.params.filename + '.json');
        }
        
        if (deletedFiles.length > 0) {
            // Log deletion
            const deleteLog = {
                action: 'delete',
                filename: req.params.filename,
                sessionId: req.params.sessionId,
                deletedBy: 'teacher',
                timestamp: new Date().toISOString(),
                ip: req.ip
            };
            
            fs.appendFileSync('logs/deletions.log', JSON.stringify(deleteLog) + '\n');
            
            res.json({
                success: true,
                message: `Deleted ${deletedFiles.length} file(s)`,
                deleted: deletedFiles
            });
        } else {
            res.status(404).json({
                error: 'File not found',
                message: 'The specified file does not exist'
            });
        }
        
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({
            error: 'Delete failed',
            message: error.message
        });
    }
});

// 8. Get Storage Statistics
app.get('/api/stats', authenticateTeacher, (req, res) => {
    const stats = getStorageStats();
    res.json(stats);
});

// 9. Clear All Uploads (Teacher access - use with caution!)
app.delete('/api/uploads', authenticateTeacher, (req, res) => {
    if (!req.query.confirm || req.query.confirm !== 'true') {
        return res.status(400).json({
            error: 'Confirmation required',
            message: 'Add ?confirm=true to confirm deletion of ALL files'
        });
    }
    
    try {
        let deletedCount = 0;
        let totalSize = 0;
        
        function deleteDirectory(dir) {
            if (fs.existsSync(dir)) {
                const items = fs.readdirSync(dir, { withFileTypes: true });
                
                items.forEach(item => {
                    const fullPath = path.join(dir, item.name);
                    
                    if (item.isDirectory()) {
                        deleteDirectory(fullPath);
                        // Remove empty directory
                        fs.rmdirSync(fullPath);
                    } else if (item.isFile()) {
                        const stat = fs.statSync(fullPath);
                        totalSize += stat.size;
                        fs.unlinkSync(fullPath);
                        deletedCount++;
                    }
                });
            }
        }
        
        deleteDirectory(CONFIG.uploadDir);
        
        // Log mass deletion
        const massDeleteLog = {
            action: 'mass_delete',
            deletedCount: deletedCount,
            totalSize: totalSize,
            timestamp: new Date().toISOString(),
            ip: req.ip
        };
        
        fs.appendFileSync('logs/deletions.log', JSON.stringify(massDeleteLog) + '\n');
        
        res.json({
            success: true,
            message: `Deleted ${deletedCount} files (${formatBytes(totalSize)})`,
            deletedCount: deletedCount,
            totalSize: totalSize,
            formattedSize: formatBytes(totalSize)
        });
        
    } catch (error) {
        console.error('Mass delete error:', error);
        res.status(500).json({
            error: 'Mass delete failed',
            message: error.message
        });
    }
});

// 10. Get Upload Logs (Teacher access)
app.get('/api/logs/:type', authenticateTeacher, (req, res) => {
    const logFile = path.join('logs', `${req.params.type}.log`);
    
    if (fs.existsSync(logFile)) {
        const logs = fs.readFileSync(logFile, 'utf8')
            .split('\n')
            .filter(line => line.trim())
            .map(line => {
                try {
                    return JSON.parse(line);
                } catch {
                    return { raw: line };
                }
            });
        
        res.json({
            success: true,
            count: logs.length,
            logs: logs
        });
    } else {
        res.status(404).json({
            error: 'Log file not found',
            message: `No ${req.params.type} logs available`
        });
    }
});

// 11. Generate Session ID for Student
app.get('/api/session', (req, res) => {
    const sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substring(2, 15);
    
    res.json({
        sessionId: sessionId,
        timestamp: new Date().toISOString(),
        expires: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
    });
});

// ========== HELPER FUNCTIONS ==========
function getStorageStats() {
    let totalFiles = 0;
    let totalSize = 0;
    let users = new Set();
    let byType = {};
    
    function scanStats(dir) {
        if (!fs.existsSync(dir)) return;
        
        const items = fs.readdirSync(dir, { withFileTypes: true });
        
        items.forEach(item => {
            const fullPath = path.join(dir, item.name);
            
            if (item.isDirectory()) {
                users.add(item.name);
                scanStats(fullPath);
            } else if (item.isFile() && !item.name.endsWith('.json')) {
                const stat = fs.statSync(fullPath);
                totalFiles++;
                totalSize += stat.size;
                
                const ext = path.extname(item.name).substring(1).toLowerCase();
                byType[ext] = (byType[ext] || 0) + 1;
            }
        });
    }
    
    scanStats(CONFIG.uploadDir);
    
    return {
        totalFiles: totalFiles,
        totalSize: totalSize,
        formattedSize: formatBytes(totalSize),
        uniqueUsers: users.size,
        filesByType: byType,
        lastUpdated: new Date().toISOString()
    };
}

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function getMimeType(filename) {
    const ext = path.extname(filename).toLowerCase();
    const mimeTypes = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.webm': 'video/webm',
        '.mp4': 'video/mp4',
        '.mov': 'video/quicktime'
    };
    
    return mimeTypes[ext] || 'application/octet-stream';
}

// ========== ERROR HANDLING ==========
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    
    // Multer errors
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({
                error: 'File too large',
                message: `File exceeds maximum size of ${formatBytes(CONFIG.maxFileSize)}`
            });
        }
        
        return res.status(400).json({
            error: 'Upload error',
            message: err.message
        });
    }
    
    // Custom errors
    if (err.message && err.message.includes('not allowed')) {
        return res.status(400).json({
            error: 'Invalid file type',
            message: err.message
        });
    }
    
    // Generic error
    res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Not found',
        message: `Cannot ${req.method} ${req.url}`
    });
});

// ========== START SERVER ==========
app.listen(PORT, () => {
    console.log(`
    🎓 SCHOOL CAMERA PROJECT SERVER
    =================================
    📍 Local URL: http://localhost:${PORT}
    👨‍🏫 Teacher Dashboard: http://localhost:${PORT}/teacher
    🔑 Teacher Token: ${CONFIG.teacherToken}
    💾 Storage: ${CONFIG.uploadDir}/
    📝 Logs: logs/
    =================================
    
    IMPORTANT: Save the teacher token above!
    Students will access: http://localhost:${PORT}
    
    To deploy online, see README.md
    `);
    
    // Log server start
    const startLog = {
        action: 'server_start',
        timestamp: new Date().toISOString(),
        port: PORT,
        config: {
            maxFileSize: CONFIG.maxFileSize,
            uploadDir: CONFIG.uploadDir
        }
    };
    
    fs.appendFileSync('logs/server.log', JSON.stringify(startLog) + '\n');
});