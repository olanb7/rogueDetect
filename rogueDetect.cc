#include <click/config.h>
#include "rogueDetect.hh"
#include <click/element.hh>
#include <click/timer.hh>
#include <clicknet/ether.h>
#include <click/etheraddress.hh>
#include <clicknet/wifi.h>
#include <click/etheraddress.hh>
#include <click/confparse.hh>
#include <click/vector.hh>
#include <elements/wifi/availablerates.hh>
#include <elements/wifi/wirelessinfo.hh>
#include <click/list.hh>
#include <click/error.hh>
#include <string>
#include <click/ewma.hh>  	// !!
#if CLICK_USERLEVEL
# include <sys/time.h>
# include <sys/resource.h>
# include <unistd.h>
#endif

#define show_debug 0		// set true to output debug messages from getStats funcion
#define window 100 		// define window size in packets

CLICK_DECLS

RogueDetect::RogueDetect()
  : _timer(this),
    _logfile(0)
{
}

RogueDetect::~RogueDetect()
{
}

int
RogueDetect::initialize (ErrorHandler *) {

	_timer.initialize(this);
	_timer.schedule_after_sec(1);
	return 0;
}

void RogueDetect::print_stations(StationList &l) {
	size_t n = 0;
	StringAccum sa, head;
	int beacon_attack = 0;

	Timestamp now = Timestamp::now();
	system("clear");

	if (show_debug)
		click_chatter("%s", debug.take_string().c_str());

	head << "\nNo.\tMAC              \tBeacons\tRSSI\tLast Packet\tEWMA  \tVariance\n";
	head <<   "---\t-----------------\t-------\t----\t-----------\t------\t--------\n";
	click_chatter("%s", head.c_str());

	for (StationList::iterator sta = l.begin(); sta != l.end(); ++sta, ++n) {
		Timestamp diff = now;
		diff -= *sta->time;
		if (diff > 90) {
			// forget if not seen in 90 secs
			l.erase(sta);
			sa << "bye bye " << sta->mac->unparse_colon().c_str() << "\n";
		}
		else {
			int len;
			len = sprintf(sa.reserve(3), "%3d", n);
			sa.adjust_length(len);

			len = sprintf(sa.reserve(18), "\t%s", sta->mac->unparse_colon().c_str());
			sa.adjust_length(len);

			len = sprintf(sa.reserve(10), "\t%7d", sta->beacon_rate);
			sa.adjust_length(len);

			len = sprintf(sa.reserve(9), "\t%4d", sta->rssi);
			sa.adjust_length(len);

			if (diff < 1) { 
				sa << "\t \e[32m  " << diff << "\e[0m"; }
			else { 	
				sa << "\t \e[31m  " << diff << "\e[0m"; }

			sa.reserve(12);
			sa << "\t" << sta->_size.unparse();

			len = sprintf(sa.reserve(12), "\t%05.3f", sta->var);
			sa.adjust_length(len);
			
			len = sprintf(sa.reserve(12), "\t%05.3f", sta->var_sh);
			sa.adjust_length(len);

			// beacon rate attack detector
			if(sta->beacon_int) {
				if ( (sta->beacon_int * sta->beacon_rate) > (11*100) ) {
					sa << "\t \e[31m Possible Attack!! \e[0m High Beacon Count ( " << sta->beacon_int << ", " << sta->beacon_rate << " )";
					beacon_attack = 1;
				}
			}

			// variance attack detector
			if(sta->var > 1000) {
					if (beacon_attack)
						sa << " AND High Variance ( " << sta->var << " )";
					else
						sa << "\t \e[31m Possible Attack!! \e[0m High Variance ( " << sta->var << " )";
			}

			sa << "\n";
		}		
	}
	click_chatter("%s", sa.c_str());
}

RogueDetect::station *
RogueDetect::lookup(station &chksta, StationList &l) {
	size_t n = 0;
	for (StationList::iterator lkup = l.begin(); lkup != l.end(); ++lkup, ++n) {

		// if MAC address is found in list, return pointer to it
		if(!strcmp(chksta.mac->unparse().c_str(), lkup->mac->unparse().c_str())) {
				return lkup.get();
		}
	}
	return (struct station*)NULL;
}

void RogueDetect::run_timer(Timer *) {

	getStats(_sta_list);
	print_stations(_sta_list);
	_timer.schedule_after_msec(1000);
}

void RogueDetect::getStats (StationList &l) {

	for (StationList::iterator sta = l.begin(); sta != l.end(); ++sta) {

		debug << "\n" << sta->mac->unparse().c_str();
		getAverage(*sta, 100);
		getVariance(*sta, 10);
		getEWMA(*sta);

		sta->flag = 1;
	}

}

void RogueDetect::getAverage(station &sta, int samples) {

	sta.ave = 0;
	if (sta.past_packets.size() < samples)
		samples = sta.past_packets.size();

	int start = sta.past_packets.size() - samples;

	debug << "\ngetAverage: ";

	if (!sta.past_packets.empty()) {
		for(int i = start; i < sta.past_packets.size(); i++) {
			debug << sta.past_packets.at(i) << " + ";
			sta.ave += sta.past_packets.at(i);
		}
		sta.ave = sta.ave / samples;
	}
	else {
		sta.ave = 0;
	}
	debug << " -> average = " << sta.ave;
}

void RogueDetect::getVariance(station &sta, int samples) {

	sta.var = 0;
	if (sta.past_packets.size() < samples)
		samples = sta.past_packets.size();

	int start = sta.past_packets.size() - samples;
	debug << "\ngetVariance: ";

	if (!sta.past_packets.empty()) {
		for(int j = start; j < sta.past_packets.size(); j++) {
			sta.var += (sta.past_packets.at(j) - sta.ave) * (sta.past_packets.at(j) - sta.ave);
			debug << sta.var << ", ";
		}
		sta.var = sta.var / samples;
	}
	else {
		sta.var = 0;
	}
	debug << " -> variance = " << sta.var;

}

void RogueDetect::getVarianceAlt(station &sta, int samples) {

	sta.var_sh = 0;
	if (sta.past_packets.size() < samples)
		samples = sta.past_packets.size();

	int start = sta.past_packets.size() - samples;


	if (!sta.past_packets.empty()) {
		for(int j = start; j < sta.past_packets.size(); j++) {
			sta.var_sh += (sta.past_packets.at(j) - sta.ave) * (sta.past_packets.at(j) - sta.ave);
			debug << sta.var_sh << ", ";
		}
		sta.var_sh = sta.var_sh / samples;
	}
	else {
		sta.var_sh = 0;
	}
}

void RogueDetect::getEWMA(station &sta) {

	if(!sta.past_packets.empty()) {
		sta._size.assign( uint64_t (sta.past_packets.at(0) << sta._size.scale()) );
		for(int i = 1; i < sta.past_packets.size(); i++) {
			sta._size.update(sta.past_packets.at(i));
		}
	}
	else {
		sta._size.update(0);
	}
}

void RogueDetect::keepTrack(station &sta){

	if (sta.past_packets.size() >= window) {
		sta.past_packets.pop_front();
	}
	// put new rssi in array
	sta.past_packets.push_back(sta.rssi);
}

void
RogueDetect::push(int, Packet *p) {

	StringAccum log, dir;

	struct click_wifi *w = (struct click_wifi *) p->data();
	struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);
	struct station *sta = new station;

	int type = w->i_fc[0] & WIFI_FC0_TYPE_MASK;
	int subtype = w->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;
	int is_mgmt = 0, is_beacon = 0,  is_data = 0;
	int not_probe_rq = 1, not_tods = 1, not_ctrl = 1; 	// things we don't want to look at
	uint8_t *ptr;
	


	// Check DS Status

	switch (w->i_fc[1] & WIFI_FC1_DIR_MASK) {
		case WIFI_FC1_DIR_NODS:
			//dst = EtherAddress(w->i_addr1);
			//src = EtherAddress(w->i_addr2);
			sta->mac = new EtherAddress(w->i_addr3);
			dir << "NoDS  ";
			break;
		case WIFI_FC1_DIR_TODS:
			
			sta->mac = new EtherAddress(w->i_addr1);	// not interested in ToDS
			//src = EtherAddress(w->i_addr2);
			//dst = EtherAddress(w->i_addr3);
			dir << "ToDS  ";
			not_tods = 0;
			break;
		case WIFI_FC1_DIR_FROMDS:
			//dst = EtherAddress(w->i_addr1);
			sta->mac = new EtherAddress(w->i_addr2);
			//src = EtherAddress(w->i_addr3);
			dir << "FromDS";
			break;
		case WIFI_FC1_DIR_DSTODS:
			//dst = EtherAddress(w->i_addr1);
			//src = EtherAddress(w->i_addr2);
			sta->mac = new EtherAddress(w->i_addr3);
			dir << "DStoDS";
			break;
		default:
			click_chatter(" ??? ");
	}	

	// If beacon, increment beason rate
	
	if (type == WIFI_FC0_TYPE_MGT) {
		is_mgmt = 1;
		if (subtype ==  WIFI_FC0_SUBTYPE_BEACON) {
			is_beacon = 1;

			// get beacon interval (ms)
			ptr = ( (uint8_t *) (w+1) ) + 8;
  			sta->beacon_int = le16_to_cpu(*(uint16_t *) ptr);
			//click_chatter("%s| %s | beacon rssi = %d", sta->mac->unparse_colon().c_str(), dir.c_str(), ceh->rssi);
		}
		else {
			if(!sta->beacon_int) {
				sta->beacon_int = 0;
			}
			//click_chatter("%s| %s | mgmt rssi = %d", sta->mac->unparse_colon().c_str(), dir.c_str(), ceh->rssi);
		}
		if (subtype == WIFI_FC0_SUBTYPE_PROBE_REQ)
			not_probe_rq = 0;
	}
	else if (type == WIFI_FC0_TYPE_DATA) {
		is_data = 1;
		//click_chatter("%s| %s | data rssi = %d", sta->mac->unparse_colon().c_str(), dir.c_str(), ceh->rssi);

	} 
	else if (type == WIFI_FC0_TYPE_CTL) {
		not_ctrl = 0;
	}

	// interrogate packets
	if (not_tods && not_ctrl && not_probe_rq) {

		// get rssi
		sta->rssi = ceh->rssi;
		
		if (_sta_list.empty()) {
			// empty, so add sta

			sta->time = new Timestamp(Timestamp::now());
			sta->first_run = 1;
			keepTrack(*sta);
			if (is_beacon)
				sta->beacon_rate = 1;
			else
				sta->beacon_rate = 0;

			log << *sta->time << "\t";
			log << sta->rssi << "\t";

			_sta_list.push_back(sta);
		}
		else {
			// list not empty, so lookup
			struct station *sta_dupe = lookup(*sta, _sta_list);
			
			// if list seen before
			if (sta_dupe) {
				sta_dupe->time->set_now();
				sta_dupe->rssi = sta->rssi;
				keepTrack(*sta_dupe);
				if (is_beacon)
					sta_dupe->beacon_rate++;
			
				log << *sta_dupe->time	<< "\t";
				log <<  sta_dupe->rssi	<< "\t";

				getVarianceAlt(*sta_dupe, 2);
				log << sta_dupe->var_sh  << "\t";
				if (sta_dupe->flag == 1) {

					log << sta_dupe->var << "\t";
					log << sta_dupe->_size.unparse()	<< "\t";
					log << sta_dupe->beacon_rate	<< "\t";
					
					sta_dupe->flag = 0;
					sta_dupe->beacon_rate = 0;
				}
			}
			// else if not seen before			
			else {
				sta->time = new Timestamp(Timestamp::now());
				sta->first_run = 1;
				keepTrack(*sta);
				if (is_beacon)
					sta->beacon_rate = 1;
				else
					sta->beacon_rate = 0;

				log << *sta->time << "\t";
				log << sta->rssi << "\t";

				_sta_list.push_back(sta);
			}
		}
		

		log << "\n";

		#if CLICK_USERLEVEL
			logOutput(*sta, log);
		#endif

		//delete sta->mac;
	}
	output(0).push(p);
}

void RogueDetect::logOutput(station &sta, StringAccum log) {

	StringAccum fn;

	// log packets to file
	fn << "/home/olan/logs/" << sta.mac->unparse().c_str() << ".txt";
	_filename = fn.take_string();

	if (_filename) {
		_logfile = fopen(_filename.c_str(), "a");
		if (!_logfile)
			click_chatter("ERROR: %s, can't open logfile for appending\n", _filename.c_str());

		fwrite(log.data(), 1, log.length(), _logfile);
	}
	else {
		click_chatter("Wrong filename : %s\n", _filename.c_str());	
	}

  	if (_logfile)
  		fclose(_logfile);
	_logfile = 0;
}

EXPORT_ELEMENT(RogueDetect)
CLICK_ENDDECLS


