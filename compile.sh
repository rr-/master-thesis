#!/bin/bash
cd "$( dirname "${BASH_SOURCE[0]}" )"
rm -f praca.pdf
pdflatex thesis.tex && pdflatex thesis.tex && clear
rm -f *.log
rm -f *.aux
rm -f *.toc
