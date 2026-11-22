module.exports = {
  apps: [{
    name: 'advisory-automation',
    script: './dist/server/src/index.js',
    node_args: '--env-file-if-exists=.env',
    cwd: __dirname,
    instances: 1,
    exec_mode: 'fork',
    autorestart: true,
    max_memory_restart: '750M',
    restart_delay: 3000,
    max_restarts: 10,
    time: true,
    env: { NODE_ENV: 'production', HOST: '0.0.0.0', PORT: '4100' }
  }]
};
