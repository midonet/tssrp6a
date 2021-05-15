const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto('http://localhost:8080/demo');

  const TEST_PASSED = await page.evaluate(async () => await window.PUPPETEER_PROMISE );
  await browser.close();
  if (TEST_PASSED) {
    console.log("TEST_PASSED: true");
  } else {
    console.log("TEST_PASSED: false");
    process.exit(1);
  }
})();
