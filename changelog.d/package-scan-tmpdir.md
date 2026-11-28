---
group: Fixed
---
the package-scan unit keeps the scanner's temporary files on disk (TMPDIR=/var/tmp): /tmp is memory-backed on the guests, and image-scan leftovers there took gigabytes of a guest's RAM.
