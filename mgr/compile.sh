#!/bin/bash
cd "$( dirname "${BASH_SOURCE[0]}" )"
rm -f thesis.pdf

pdflatex -interaction=batchmode -file-line-error thesis.tex && \
bibtex thesis.aux && \
pdflatex -interaction=batchmode -file-line-error thesis.tex && \
pdflatex -interaction=batchmode -file-line-error thesis.tex && \
clear

rm -f *.aux *.toc *.bbl *.blg
