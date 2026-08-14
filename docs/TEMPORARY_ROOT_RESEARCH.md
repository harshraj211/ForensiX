# Temporary-root research candidates

The first candidate is deliberately narrow: Google Pixel 2 (`walleye`) and Pixel 2 XL (`taimen`)
on Android 10 build `QP1A.190711.020`, September 2019 security patch, and kernel build ID
`4.4.177-g83bee1dc48e8`.

The public research implementation identifies this exact Pixel 2/2 XL build as its target for
CVE-2019-2215. Google’s October 2019 Pixel bulletin states that Pixel 1 and Pixel 2 received the
fix in the October update, so a later patch must not be treated as eligible.

This is a research candidate, not a supported ForensiX provider. The repository keeps it separate
from the executable provider registry. Before enabling it, the team must:

- obtain a lab Pixel 2 or Pixel 2 XL with the exact build and kernel;
- verify the live properties and kernel release without flashing an evidence device;
- review the provider’s license and provenance;
- run crash, reboot, SELinux, data-integrity, and cleanup tests on a sacrificial device;
- record a signed validation report and provider SHA-256; and
- add a reviewed `TemporaryRootProfile` only after those checks pass.

The public source explicitly warns that its tool is educational, may crash or lose data, and is
not guaranteed on other devices or kernels. It must not be copied into a production bundle solely
because the model and Android release match.
