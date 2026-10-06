# Chrome evidence for necronicle/d2k PR #17

These are original PNG files from the successful GitHub Actions job:
https://github.com/necronicle/d2k/actions/runs/37458254546/job/112251082243

Tested PR head: f8339ee7e54fa8849a4821a5cfe633c742b4ca0f
Browser: Chrome 154.0.8037.92, headless Linux runner.
The C panel was built and served through panel/browser-c-fixture.cjs.

before-649x1020.png uses panel.css from main 3a3b341eaded9c255d5931bf7446b2beb50607bc with the new regression harness. It fails specifically because the reapply control overlaps the logo.
after-*.png use the PR CSS and JavaScript. All 15 viewport checks pass, including visible 44px control targets, no intersections with the logo/status/other controls, no horizontal overflow, and sticky navigation below the actual masthead after scrolling 400px.

Full original artifact (31 screenshots and fixed/baseline logs):
https://github.com/necronicle/d2k/actions/runs/37458254546/artifacts/11411116591

This evidence does not include Safari or a live router test.
