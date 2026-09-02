# Container Runtime Security: Comparative Insights

A technical paper that compares detection, response, and prevention across Falco, Tetragon, Tracee,
NeuVector, gVisor, Prisma, and KubeArmor. It explains the kernel primitives each engine depends on,
and what each primitive can and cannot enforce.

📄 **[Read the paper](./Container-Runtime-Security-Comparative-Insights.pdf)** (PDF, 24 pages)

Rahul Jadhav, a maintainer of KubeArmor, wrote it. The KubeArmor project publishes it.

## What it covers

| Section | Question it answers |
|---|---|
| Characteristics of a runtime security solution | What can eBPF observe, and what can it actually block? |
| Time-of-check to time-of-use | Why does an argument read on syscall exit let a rule be bypassed? |
| Event loss under load | What happens to a response when the ring buffer overflows? |
| Sandboxing | Which engines can gate every action, rather than react to one? |
| Engine analysis | How does each of the seven engines enforce, at the primitive level? |
| Case study | Can each engine stop a file from being deleted, not just report it? |

## Building the PDF

The PDF is committed, so you only need this if you change the source.

```bash
pip install playwright pymupdf && python -m playwright install chromium
python src/build.py
```

The build fetches Poppins, Source Serif 4, and Source Code Pro into `src/.fonts/` on the first run,
then caches them. It lays out the body and the two full-bleed covers in
separate passes, then splices them. It resolves the table of contents page numbers over two
renders. It stamps the running foot, the PDF outline, and the document metadata.

| File | What it is |
|---|---|
| `src/paper.html` | The full text of the paper, as semantic HTML. |
| `src/paper.css` | Print stylesheet. Palette and type follow the KubeArmor brand tokens on [kubearmor.io](https://kubearmor.io). |
| `src/build.py` | The build pipeline described above. |
| `src/figures/` | Diagrams referenced by the paper. |
| `src/brand/` | KubeArmor and CNCF marks used on the covers. |

## Corrections

Engines change. If a claim in the paper no longer holds, open a thread in
[GitHub Discussions](https://github.com/kubearmor/KubeArmor/discussions) or raise it in
`#kubearmor` on [CNCF Slack](https://cloud-native.slack.com/archives/C02R319HVL3). Edit
`src/paper.html`, rebuild, and send both the source change and the regenerated PDF in one pull
request.
