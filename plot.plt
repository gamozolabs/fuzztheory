set terminal wxt size 1440,900
#set output "output.png"
set logscale xy
set grid
set title "Time to find all known bugs with different fuzzer configurations"
set xlabel "Number of Cores"
set ylabel "Average \"time\" to all bugs and coverage (in fuzz cases / cores)"
set key left
plot "coverage_false_collab_false.txt" u 1:2 w l t "Nothing at all", \
     "coverage_false_collab_true.txt" u 1:2 w l t "Collaborative", \
     "coverage_true_collab_false.txt" u 1:2 w l t "Coverage guided", \
     "coverage_true_collab_true.txt" u 1:2 w l t "Coverage guided, collaborative"

