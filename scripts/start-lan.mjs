process.env.NODE_ENV = 'production';
process.env.HOST = process.env.ADVISORY_LAN_ADDRESS || '0.0.0.0';
await import('../dist/server/src/index.js');
