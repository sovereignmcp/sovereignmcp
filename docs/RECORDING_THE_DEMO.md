# Recording the 60-second demo GIF

What to show: the stack starting, then the 15-step demo. The story is the demo: the intern's assistant can't see `delete_database`, `rm -rf /` and the metadata URL are blocked, a `DELETE` is held, the manager approves, it runs once.

## Easiest on Windows: ScreenToGif (free)
1. `docker compose up -d` and wait about 10 seconds. Make your terminal font large (18+) and the window small (about 100x28).
2. Open ScreenToGif, choose **Recorder**, frame the terminal.
3. Press record, run: `python examples/demo_client.py --short`
4. Stop after the last line says **ALL STEPS PASSED**. Trim the start and end, set frame rate to 10-15 fps, export as GIF.
5. Save as `docs/demo.gif`. Keep it **under about 5 MB** (shrink the window or the duration if larger).
6. Open `README.md` and uncomment the `![60-second demo](docs/demo.gif)` line.

## Reproducible alternative (VHS, any OS)
Install [VHS](https://github.com/charmbracelet/vhs) with its dependencies, run `docker compose up -d`, then: `vhs docs/demo.tape`
This writes `docs/demo.gif` from the script in `docs/demo.tape`.

## A 60-second video for X / LinkedIn
Same recording, plus your voice: 1) "an intern asks the AI to clean up test data", 2) "without a gateway it deletes production", 3) the demo, 4) "link in the post". Show the real output only; never edit results.
