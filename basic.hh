#ifndef CLICK_BASIC_HH
#define CLICK_BASIC_HH
#include <click/element.hh>
#include <click/timer.hh>
#include <clicknet/ether.h>
#include <click/etheraddress.hh>
#include <click/dequeue.hh>
#include <clicknet/wifi.h>
#include <click/etheraddress.hh>
#include <click/confparse.hh>
#include <click/glue.hh>
#include <clicknet/llc.h>
#include <click/straccum.hh>
#include <click/vector.hh>
#include <click/hashmap.hh>
#include <click/packet_anno.hh>
#include <elements/wifi/availablerates.hh>
#include <elements/wifi/wirelessinfo.hh>
#include <click/list.hh>
#include <click/error.hh>
#if CLICK_USERLEVEL
# include <sys/time.h>
# include <sys/resource.h>
# include <unistd.h>
#endif
#include <click/ewma.hh>

CLICK_DECLS

class Basic : public Element {

public:

  Basic();
  ~Basic();

  typedef DirectEWMAX<FixedEWMAXParameters<1, 10, uint64_t, int64_t> > ewma_type;

  struct station {
	EtherAddress *mac;
	Timestamp *time;

	List_member<station> link;
	Vector<int> past_packets;

	double ave, ema, var, stddev; 
	int rssi, flag, first_run, pps;

	ewma_type _size;
	ewma_type _sec_size;
	};

  
  typedef List<station, &station::link> StationList;
  StationList _sta_list;

  const char *class_name() const	{ return "Basic"; }
  const char *port_count() const	{ return PORTS_1_1; }
  const char *processing() const	{ return PUSH; }
  
  void push (int port, Packet *);
  void run_timer (Timer *);
  void print_stations (StationList &l);
  void getStats (StationList &l);
  int  initialize (ErrorHandler *);
  void keepTrack (station &);

  Basic::station * lookup(station &, StationList &);
  
  //const ewma_type const { return _size; }

  Timer _timer;
  String _filename;
  FILE *_logfile; 
  double alpha;

  double k;  

};
CLICK_ENDDECLS
#endif
