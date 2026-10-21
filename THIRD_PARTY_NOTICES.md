# Third-Party Software Notices and Information

This project, **PKT Security Platform Next**, integrates, depends on, or interacts with third-party software components and external security scanner tools. This document provides the required copyright notices, licenses, and legal design rationales for each component in compliance with their respective open-source licenses.

---

## 1. Integrated External Security Scanners

PKT Security Platform Next orchestrates external scanning tools via isolated, out-of-process CLI invocations and standard SARIF/CycloneDX streaming interfaces.

| Tool | Upstream Project / Author | License | Integration Method |
| :--- | :--- | :--- | :--- |
| **Trivy** | Aqua Security Software Ltd. | Apache License 2.0 | Out-of-process CLI (`trivy fs ... --format sarif`) |
| **Semgrep OSS** | Semgrep, Inc. | GNU Lesser General Public License v2.1 (LGPL-2.1) | Out-of-process CLI (`semgrep scan ... --sarif`) |
| **Gitleaks** | Zachary Rice | MIT License | Out-of-process CLI (`gitleaks dir ... --report-format sarif`) |
| **OSV-Scanner** | Google LLC | Apache License 2.0 | Out-of-process CLI (`osv-scanner ... --format sarif`) |
| **Syft** | Anchore, Inc. | Apache License 2.0 | Out-of-process CLI (`syft scan ... -o cyclonedx-json`) |
| **Grype** | Anchore, Inc. | Apache License 2.0 | Out-of-process CLI (`grype ... -o sarif`) |

---

### Special Notice: Legal & Architectural Rationale for Semgrep (LGPL-2.1)

#### A. Architecture and Loose Coupling Design
- **No In-Process / Static Linking**: PKT Security Platform Next does **not** link (statically or dynamically) against Semgrep libraries or internal binaries. The C# codebase operates strictly as a separate caller invoking the external `semgrep` binary executable via standard OS process execution (`ProcessStartInfo`).
- **Standard Protocol Interchange**: Communication between PKT Security Platform Next and Semgrep occurs solely via standard command-line parameters, standard input/output streams, and open standard data formats (OASIS SARIF 2.1.0).
- **Independent Execution & Replaceability**: The user or deploying organisation can update, modify, or substitute the underlying Semgrep executable without re-compiling, modifying, or impacting PKT Security Platform Next.

#### B. Commercial Use & Proprietary Rules Considerations
- **Open-Source Engine vs Proprietary Rules**: The open-source CLI engine (`semgrep-core`) is licensed under LGPL-2.1. However, Semgrep Inc. distributes certain rules and features under proprietary terms ("Semgrep Rules License" / "Semgrep Pro"). PKT Security Platform Next does not bundle or re-distribute proprietary Semgrep rules.
- **Compliance Obligations**: Deployers are responsible for adhering to their own usage agreements if configuring proprietary Semgrep Registry tokens or rule subscriptions. Standard open-source rules (`p/default`, `p/owasp-top-ten`, `p/cwe-top-25`) may be used under their applicable public licenses.

---

## 2. Backend NuGet Dependencies (.NET 8)

The following NuGet packages are utilized in the backend solution:

| Package | Authors / Copyright | License |
| :--- | :--- | :--- |
| `Npgsql` | Npgsql Development Team | PostgreSQL License |
| `Npgsql.EntityFrameworkCore.PostgreSQL` | Npgsql Development Team | PostgreSQL License |
| `Microsoft.EntityFrameworkCore` | Microsoft Corporation | MIT License |
| `Microsoft.EntityFrameworkCore.Relational` | Microsoft Corporation | MIT License |
| `Microsoft.EntityFrameworkCore.Design` | Microsoft Corporation | MIT License |
| `Microsoft.AspNetCore.Authentication.JwtBearer` | Microsoft Corporation | MIT License |
| `Microsoft.Extensions.Caching.Memory` | Microsoft Corporation | MIT License |
| `OpenTelemetry` | OpenTelemetry Authors | Apache License 2.0 |
| `OpenTelemetry.Extensions.Hosting` | OpenTelemetry Authors | Apache License 2.0 |
| `OpenTelemetry.Instrumentation.AspNetCore` | OpenTelemetry Authors | Apache License 2.0 |
| `OpenTelemetry.Instrumentation.Http` | OpenTelemetry Authors | Apache License 2.0 |
| `Dapper` | Stack Exchange, Inc. and contributors | Apache License 2.0 |
| `BCrypt.Net-Next` | Chris McKee, Ryan D. Emerle | MIT License |
| `Swashbuckle.AspNetCore` | Richard Morris, domaindrivendev | MIT License |
| `System.IdentityModel.Tokens.Jwt` | Microsoft Corporation | MIT License |
| `Microsoft.NET.Test.Sdk` | Microsoft Corporation | MIT License |
| `xunit` | James Newkirk, Brad Wilson | Apache License 2.0 |
| `xunit.runner.visualstudio` | James Newkirk, Brad Wilson | Apache License 2.0 |
| `coverlet.collector` | Toni Solarin-Sodara | MIT License |
| `Microsoft.AspNetCore.Mvc.Testing` | Microsoft Corporation | MIT License |

---

## 3. Frontend npm Dependencies (Next.js / React)

The frontend application (`src/PktSecurity.Web`) utilizes the following npm packages:

| Package | Authors / Maintainers | License |
| :--- | :--- | :--- |
| `next` | Vercel, Inc. | MIT License |
| `react` | Meta Platforms, Inc. | MIT License |
| `react-dom` | Meta Platforms, Inc. | MIT License |
| `lucide-react` | Lucide Contributors | ISC License |
| `tailwindcss` | Tailwind Labs, Inc. | MIT License |
| `postcss` | Andrey Sitnik | MIT License |
| `autoprefixer` | Andrey Sitnik | MIT License |
| `typescript` | Microsoft Corporation | Apache License 2.0 |
| `@types/node` | DefinitelyTyped | MIT License |
| `@types/react` | DefinitelyTyped | MIT License |
| `@types/react-dom` | DefinitelyTyped | MIT License |

---

## 4. Full License Texts

### Apache License 2.0
```
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

### MIT License
```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### PostgreSQL License
```
Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
Portions Copyright (c) 1994, The Regents of the University of California

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose, without fee, and without a written agreement
is hereby granted, provided that the above copyright notice and this
paragraph and the following two paragraphs appear in all copies.

IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
```

### ISC License
```
Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

### GNU Lesser General Public License v2.1 (LGPL-2.1)
```
Semgrep OSS is licensed under the GNU Lesser General Public License v2.1.
A complete copy of the GNU Lesser General Public License v2.1 can be obtained at:
https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html
```
