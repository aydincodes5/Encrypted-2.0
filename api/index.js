'use strict';

// Vercel serverless entrypoint. Vercel owns the HTTP server, so this module
// exports the Express app instead of opening a port.
const { app, initialiseApp } = require('../server');

module.exports = async (req, res) => {
  try {
    await initialiseApp();
    return app(req, res);
  } catch (error) {
    console.error('Application initialisation failed:', error);
    return res.status(500).json({ error: 'Database connection failed.' });
  }
};
