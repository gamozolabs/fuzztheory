set terminal wxt size 1440,900
#set output "output.png"
set logscale xy
set grid
set title "Coverage numbers with a given number of cores at a fixed time budget"
set xlabel "Number of Cores"
set ylabel "Coverage numbers at a fixed time limit"
set key font "monospace,14"
set key left
plot \
    "coverage_false_inputshare_false_resultshare_false.txt" u 1:2 w lp t "Feedback: No,  Share input: No,  Share results: No ", \
    "coverage_false_inputshare_false_resultshare_true.txt" u 1:2 w lp  t "Feedback: No,  Share input: No,  Share results: Yes", \
    "coverage_false_inputshare_true_resultshare_false.txt" u 1:2 w lp  t "Feedback: No,  Share input: Yes, Share results: No ", \
    "coverage_false_inputshare_true_resultshare_true.txt" u 1:2 w lp   t "Feedback: No,  Share input: Yes, Share results: Yes", \
    "coverage_true_inputshare_false_resultshare_false.txt" u 1:2 w lp  t "Feedback: Yes, Share input: No,  Share results: No ", \
    "coverage_true_inputshare_false_resultshare_true.txt" u 1:2 w lp   t "Feedback: Yes, Share input: No,  Share results: Yes", \
    "coverage_true_inputshare_true_resultshare_false.txt" u 1:2 w lp   t "Feedback: Yes, Share input: Yes, Share results: No ", \
    "coverage_true_inputshare_true_resultshare_true.txt" u 1:2 w lp    t "Feedback: Yes, Share input: Yes, Share results: Yes"

