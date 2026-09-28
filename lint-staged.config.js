module.exports = {
  // tsc 7 refuses file args when tsconfig.json exists, so type-check the whole project
  "*.ts": ["biome check --write", () => "tsc --noEmit"],
  "README.md": "doctoc --update-only --maxlevel 3 --minlevel 2 --notitle",
};
