#!/bin/sh
rm -f praca.pdf
pdflatex thesis.tex && pdflatex thesis.tex && clear
rm -f *.log
rm -f *.aux
rm -f *.toc
