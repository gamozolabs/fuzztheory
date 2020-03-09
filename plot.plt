set terminal wxt size 3000,2000
#set output "output.png"
set logscale xy
set grid
set title "Time to find all known bugs with different fuzzer configurations"
set xlabel "Number of Cores"
set ylabel "Average \"time\" to all bugs and coverage (in fuzz cases / cores)"
set key font "monospace,14"
set key right
plot \
    "coverage_false_inputshare_false_resultshare_false.txt" u 1:2 w lp t "Feedback: No,  Share input: No,  Share results: No ", \
    "coverage_false_inputshare_false_resultshare_true.txt" u 1:2 w lp  t "Feedback: No,  Share input: No,  Share results: Yes", \
    "coverage_false_inputshare_true_resultshare_false.txt" u 1:2 w lp  t "Feedback: No,  Share input: Yes, Share results: No ", \
    "coverage_false_inputshare_true_resultshare_true.txt" u 1:2 w lp   t "Feedback: No,  Share input: Yes, Share results: Yes", \
    "coverage_true_inputshare_false_resultshare_false.txt" u 1:2 w lp  t "Feedback: Yes, Share input: No,  Share results: No ", \
    "coverage_true_inputshare_false_resultshare_true.txt" u 1:2 w lp   t "Feedback: Yes, Share input: No,  Share results: Yes", \
    "coverage_true_inputshare_true_resultshare_false.txt" u 1:2 w lp   t "Feedback: Yes, Share input: Yes, Share results: No ", \
    "coverage_true_inputshare_true_resultshare_true.txt" u 1:2 w lp    t "Feedback: Yes, Share input: Yes, Share results: Yes"

