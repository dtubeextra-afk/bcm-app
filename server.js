{
  "name": "securecode",
  "version": "2.0.0",
  "description": "SECURECODE — Encrypted Messaging App",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "express-session": "^1.17.3",
    "bcrypt": "^5.1.1",
    "connect-sqlite3": "^0.9.13",
    "better-sqlite3": "^9.4.3",
    "uuid": "^9.0.0",
    "helmet": "^7.1.0",
    "cors": "^2.8.5"
  },
  "devDependencies": {
    "nodemon": "^3.0.3"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
