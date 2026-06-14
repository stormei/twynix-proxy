const fs = require('fs');

function readEnvSecret(name, env = process.env) {
  const fileVar = `${name}_FILE`;
  const filePath = env[fileVar];
  if (filePath) {
    return fs.readFileSync(filePath, 'utf8').trim();
  }
  return env[name];
}

module.exports = {
  readEnvSecret
};
