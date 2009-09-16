#! /usr/bin/env python
"""
watchPlot.py

Run this to watch the plot of a file in gnuplot as the file is appended.
Only looks at last 120 seconds of the plot. A compararison of two files 
can be achieved by entering "c X" at the prompt, where X is the number
of comparisons you wish to carry out. A simple plot can be achieved by
simply entering the logs corresponding list number.
"""

from numpy import *
import signal 
import sys
import subprocess
import os, re, glob, time
import Gnuplot, Gnuplot.funcutils

logpath = '/home/olan/logs'
compare = []
#toprint = 1

def watch():
	# set up plot
	g = Gnuplot.Gnuplot()
	g('set xlabel "Time (s)"')
	g('set key bmargin center horizontal')
	g('set data style lines')
	g('set xrange [-1800:0]')
	g('set ytics nomirror')
	g('set tics out')
	g('set size 1,1')

	# change to black background
	#g('set border 31 linetype 2')
	#g('set border linecolor rgb "white"')
	#g('set obj 1 rectangle behind from screen 0,0 to screen 1,1')
	#g('set obj 1 fillstyle solid 1.0 fillcolor rgb "#808080"')
   	
	i = 1	
	# infinite while loop
	while i:
		try:
			r_plot = "plot "
			v_plot = "plot "
			b_plot = "plot "
			
			for file in compare:
				# vanity sake
				file_sh = file.split('.')
				nicefile = file_sh[0].replace('-', ':')

				# for each file, create temp with last 1000*1800 packets
				temp = log_folder + '/.temp' + file + '.dat'
				os.system('tail -n 1800000 ' + log_folder + '/' + file + ' > ' + temp)

				# create plot string
				# 1:time | 2:rssi | 3:shortVariance | 4:Beacon Jitter | 5:longVariance | 6:RSSI EWMA | 7:Beacon Rate | 8:Avg Beacon			
				
				# RSSI's
				r_plot += "'%s' using ($1-%s):2 title 'RSSI'" % (temp, str(time.time()))
				r_plot += ", '%s' using ($1-%s):6 title 'RSSI EMA' with lines" % (temp, str(time.time()))
				
				# Variances
				v_plot += "'%s' using ($1-%s):3 title 'Short Variance'" % (temp, str(time.time()))
				v_plot += ", '%s' using ($1-%s):5 title 'Long Variance'" % (temp, str(time.time()))

				# Beacons
				
				b_plot += "'%s' using ($1-%s):7 title 'Beacons Per Sec'" % (temp, str(time.time()))
				b_plot += ", '%s' using ($1-%s):($8/1000000) title 'Beacon Jitter Avg/Sec' axes x1y2" % (temp, str(time.time()))
				b_plot += ", '%s' using ($1-%s):($4/1000000) title 'Beacon Jitter' axes x1y2" % (temp, str(time.time()))
			
				if file != compare[-1]:
					r_plot += ", "
					v_plot += ", "
					b_plot += ", "
					

			if i >= 10: 
				# for eps output
				g('set term postscript eps enhanced solid colour size 12cm,18cm')
				g('set output "/tmp/%s_%s.eps"' % ( file_sh[0], time.ctime()) )
				i = 0;
			else:				
				# reset terminal
				g('set term wxt')
				g('set size 1,1')
			
			# plot
			g('set multiplot layout 3, 1 title "Comparing Metrics of %s for Rogue AP Detection"' % (nicefile))
			g.title('Received Signal Strength Index')
			g('set ylabel "Signal/Noise Ratio"')
			g('set rmargin 6')
			g(r_plot)
			
			g.title('Variance of RSSI')
			g('set ylabel "Variance"')
			g(v_plot)

			g.title('Beacon Rate and Jitter')
			g('set ylabel "Beacon Rate (per sec)"')
			g('set y2tics')
			g('set y2label "Beacon Jitter (seconds)"')
			g('set y2range [0:0.1024]')
			g(b_plot)
			g('unset y2tics')
			g('unset y2label')
			g('unset y2range')

			g('unset multiplot')	
			i=i+2

			# sleep for a second (necessary)
			time.sleep(3)
			
		except KeyboardInterrupt:
			print "\nExiting...."
			for file in compare:
				temp = log_folder + '/.temp' + file + '.dat'
				os.system('rm ' + temp)
			i = 0
		

if __name__ == '__main__':

	logfiles = []
	chosen = 0
	i = 0

	for name in glob.glob(logpath + '/*.txt'):
		i = i+1       
		stats = os.stat(name)
		lastmod_date = time.localtime(stats[8])
		data_file_tuple = lastmod_date, name, i
		logfiles.append(data_file_tuple)

	logfiles.sort()
	logfiles.reverse()

	print "-"*8 + "log file" + "-"*16 + "last modified" + "-"*5

	for file in logfiles:
		(log_folder, log_name) = os.path.split(file[1])
		log_date = time.strftime("%H:%M:%S %m/%d/%y", file[0])
		print "%d |\t%s\t%s" % (file[2], log_name, log_date)
	
	print "-"*50

	i = 0
	c = 1
	input_text = 	"Enter log number or 'c x' to compare\nwhere x is no. of comparisons.......:"
	while i != c:	

		try:
			k = raw_input(input_text + " ")

			# check if compare
			if k[0] == 'c' and len(k) > 2:
				c = int(k[2])
				
				if c == 0 or c == 1:
					c = 1
					input_text = "Can only compare 2 or more lists. Enter again:";
				else:		
					input_text = "First compare file:"
			
			# if not compare, ensure is number
			elif k.isdigit() != True:
				raise TypeError

			# if not compare, but digit, ensure digit is in list
			else:
				for file in logfiles:
					if k == "%d" % file[2]:
						(log_folder, log_name) = os.path.split(file[1])
							
						while i < c:
							compare.append("%s" % log_name)
							i += 1
							break

						if c > 1:
							input_text = "Next compare file:"
						else:
							print "Plotting: %s" % log_name

		except KeyboardInterrupt:
			print "\nExiting....\n"
			sys.exit(0)
		except TypeError, IndexError:
			input_text = "That's not in list. Choose again:"

	watch()
