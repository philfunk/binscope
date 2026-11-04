"""binscope demo — a Hugging Face Space (Gradio).

Upload a binary and get binscope's **static triage** report: file type, entropy,
notable strings, suspicious API references, crypto constants, and a severity-
ranked findings table.

SAFETY: this Space runs only the `triage` stage, which never executes the
uploaded file. binscope's dynamic/fuzzing stages (Frida, strace/ltrace, AFL++)
are deliberately NOT available here — running untrusted binaries belongs in a
disposable, network-contained sandbox, never in a shared public Space.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import gradio as gr

from binscope.config import Config
from binscope.pipeline import Pipeline

MAX_BYTES = 25 * 1024 * 1024  # 25 MB upload cap for the demo


def analyze(file_path: str):
    if not file_path:
        return "Upload a file to analyze.", None, None
    p = Path(file_path)
    size = p.stat().st_size
    if size > MAX_BYTES:
        return (f"File is {size/1e6:.1f} MB; the demo cap is 25 MB.", None, None)

    with tempfile.TemporaryDirectory() as td:
        cfg = Config(target=p, out_dir=Path(td), stages=["triage"])
        report = Pipeline(cfg).run()

        rows = []
        for stage in report.stages:
            for f in stage.findings:
                rows.append([
                    f.severity.value.upper(),
                    f.title,
                    f.coordinate,
                    ", ".join(f.tags),
                ])
        # Most severe first.
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
        rows.sort(key=lambda r: order.get(r[0], 9))

        t = report.target
        header = (
            f"**{p.name}** — {t.filetype} ({t.family}, {t.arch}/{t.bits}-bit)  \n"
            f"size {t.size:,} bytes · entropy {t.entropy:.2f} bits/byte  \n"
            f"`sha256 {t.sha256}`"
        )
        md = report.to_markdown()
        json_path = Path(td).parent / f"{p.stem}-binscope.json"
        json_path.write_text(report.to_json(), encoding="utf-8")
        # Copy JSON out of the temp dir so Gradio can serve it.
        persist = Path(tempfile.gettempdir()) / json_path.name
        persist.write_text(report.to_json(), encoding="utf-8")

    return header, rows, str(persist)


with gr.Blocks(title="binscope") as demo:
    gr.Markdown(
        "# 🔎 binscope — static binary triage\n"
        "Upload a compiled binary (ELF / PE / Mach-O / …) to get a quick "
        "**static** report: file type, entropy, strings, suspicious API "
        "references, crypto constants, and severity-ranked findings.\n\n"
        "> This demo runs only the safe `triage` stage — it **never executes** "
        "your file. The full binscope pipeline (Ghidra, Rizin, capa, angr, "
        "Frida, AFL++) runs locally from the "
        "[GitHub repo](https://github.com/philfunk/binscope)."
    )
    with gr.Row():
        inp = gr.File(label="Binary to analyze", type="filepath")
        btn = gr.Button("Analyze", variant="primary")
    header = gr.Markdown()
    table = gr.Dataframe(
        headers=["severity", "finding", "coordinate", "tags"],
        label="Findings (most severe first)",
        wrap=True,
    )
    report_json = gr.File(label="Full report (JSON)")

    btn.click(analyze, inputs=inp, outputs=[header, table, report_json])
    inp.change(analyze, inputs=inp, outputs=[header, table, report_json])

if __name__ == "__main__":
    demo.launch()
