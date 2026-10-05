# Apache License 2.0

Copyright (c) 2024 The ChronoTrace Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

## Notice on third-party components

ChronoTrace links against or bundles third-party libraries. Their licenses are enumerated
in `NOTICE` and `third_party/licenses/`. Notable components:

| Component | License | Use |
|---|---|---|
| `pyewf` / `libewf` | LGPL-3.0 | E01/EWF evidence container reading |
| `libtsk` / `pytsk3` | IPL-1.0 / CPL | Filesystem parsing |
| `python-registry` | Apache-2.0 | Registry hive parsing |
| `Evtx` | Apache-2.0 | Windows Event Log parsing |
| `pyarrow` | Apache-2.0 | Parquet timeline storage |
| `Jinja2` | BSD-3-Clause | Report templating |
| `WeasyPrint` | BSD-3-Clause | PDF report rendering |

**Distributors:** if you redistribute binaries, you must comply with the LGPL obligations
for `libewf` (dynamic linking and relinkability). See `docs/INSTALLATION.md`.

---

## Legal disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

Use of this software for examination of systems or data without proper legal authority
may violate applicable law. The authors accept no liability for misuse.
