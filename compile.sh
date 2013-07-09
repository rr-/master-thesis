#!/bin/sh
rm praca.pdf
pdflatex thesis.tex && clear
rm *.log
rm *.aux
