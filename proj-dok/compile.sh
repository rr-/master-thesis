#!/bin/bash
cd "$( dirname "${BASH_SOURCE[0]}" )"
rm -f documentation.pdf

pdflatex -interaction=batchmode -file-line-error documentation.tex && \
bibtex documentation.aux && \
pdflatex -interaction=batchmode -file-line-error documentation.tex && \
pdflatex -interaction=batchmode -file-line-error documentation.tex

rm -f *.aux *.toc *.bbl *.blg
