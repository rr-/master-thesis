#!/bin/bash
cd "$( dirname "${BASH_SOURCE[0]}" )"
rm -f praca.pdf

pdflatex thesis.tex && \
bibtex thesis.aux && \
pdflatex thesis.tex && \
clear

rm -f *.log *.aux *.toc *.bbl *.blg
