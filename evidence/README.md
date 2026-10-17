# Evidence and provenance

V2 contains 27 curated screenshots in screenshots/, selected from 65 private originals. Files were renamed in English for navigation. Two images, validation/python-unit-tests-masked.png and validation/portable-report-masked.png, have opaque black masks covering personal workstation paths and a personalised report filename. All other pixels of those two images were verified unchanged; the remaining selected image copies were checked against their sources by SHA-256.

The originals and discarded duplicates remain private. Masks do not change test results. Generic lab names, private 192.168.56.x addresses, account names, event identifiers and historical timestamps are intentionally retained.

- Dashboard screenshots show the lab's observed alerts, not confirmed incidents.
- Report screenshots present selected exports and are not independent detector tests.
- Terminal screenshots record user-performed checks; they do not establish ongoing service health.
- replay-ssh/ contains real-engine historical output, distinct from unit-test mocks.
- The V1 screenshots remain under docs/screenshots/ to preserve existing scenario links and historical context.

Local OCR of the original lot and a visual review of the selected images supported the privacy check. No identified secret is knowingly included; this does not guarantee that every possible sensitive fact has been found. The full private archives, enrollment files and original user-path terminal captures are excluded from this repository.
