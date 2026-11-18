module.exports = {
  apps: [
    {
      name: 'simvault',
      script: 'node_modules/.bin/tsx',
      args: 'server.ts',
      cwd: __dirname + '/..',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      max_memory_restart: '512M',
      env: {
        NODE_ENV: 'production',
        HOST: '127.0.0.1',
        PORT: 3000,
      },
    },
  ],
};
