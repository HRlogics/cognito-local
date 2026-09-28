module.exports = {
  // tsc 7 refuses file args when tsconfig.json exists, so type-check the whole project
  "*.ts": ["biome check --write", () => "tsc --noEmit"],
  "README.md": "markdown-toc -i --bullets=- --maxdepth=3",
};
