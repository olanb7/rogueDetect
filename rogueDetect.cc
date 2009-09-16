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
#include <click/error.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/packet_anno.hh>
#include <click/straccum.hh>
#include <clicknet/wifi.h>
#if CLICK_USERLEVEL
# include <sys/time.h>
# include <sys/resource.h>
# include <unistd.h>
#endif

#define show_debug 0		// output debug messages from getStats funcion
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

void RogueDetect::run_timer(Timer *) {

	getStats(_sta_list);
	printStations(_sta_list);
	cleanup(_sta_list);

	_timer.schedule_after_msec(1000);
}

void RogueDetect::cleanup (StationList &l) {

	for (StationList::iterator sta = l.begin(); sta != l.end(); ++sta) {

		sta->flag = 1;
		sta->shortVar_flag = 0;
		//sta->beacon_rate = 0;
		sta->jitter = 0;
		sta->salvaged = 0;
		goodcrc = 0;
		badcrc = 0;
	}
}

void RogueDetect::printStations(StationList &l) {
	
	size_t n = 0;
	StringAccum sa, head;

	Timestamp now = Timestamp::now();
	system("clear");

	if (show_debug)
		click_chatter("%s", debug.take_string().c_str());

	head << "\nNo.\tMAC              \tBeacons\tJitter\tRSSI\tLast Packet\tEWMA  \tVariance (l & s) \n";
	head <<   "---\t-----------------\t-------\t------\t----\t-----------\t------\t-----------------\n";
	click_chatter("%s", head.c_str());

	for (StationList::iterator sta = l.begin(); sta != l.end(); ++sta, ++n) 	{
		
		Timestamp diff = now;
		diff -= *sta->time;
		
		if (diff > 90) {	// forget if not seen in 90 secs
			l.erase(sta);
			sa << "bye bye " << sta->mac->unparse_colon().c_str() << "\n";
		}
		else {			// else print stats
			int len;
			len = sprintf(sa.reserve(3), "%3d", n);
			sa.adjust_length(len);

			len = sprintf(sa.reserve(18), "\t%s", sta->mac->unparse_colon().c_str());
			sa.adjust_length(len);

			len = sprintf(sa.reserve(9), "\t%2d (%1d)", (sta->beacon_rate + sta->salvaged), sta->salvaged);
			sa.adjust_length(len);

			if (sta->beacon_rate == 0)
				len = sprintf(sa.reserve(14), "\tn/a");
			else
				len = sprintf(sa.reserve(14), "\t%d us", (sta->jitter / sta->beacon_rate));

			sa.adjust_length(len);

			len = sprintf(sa.reserve(9), "\t%4d", sta->rssi);
			sa.adjust_length(len);
			
			if (diff < 1) { 
				sa << "\t \e[32m  " << diff << "\e[0m"; }
			else { 	
				sa << "\t \e[31m  " << diff << "\e[0m"; }

			sa << "\t" << sta->_ewma.unparse() << " ";

			len = sprintf(sa.reserve(9), "\t%-4.01f", sta->longVar);
			sa.adjust_length(len);

			len = sprintf(sa.reserve(9), "\t%-4.01f ", sta->shortVar);
			sa.adjust_length(len);

			sa << "\t";
		
			// ATTACK DETECTOR
			// long variance over 20 for two or more seconds and beacon rate above normal (strong attack)
			if ( (sta->var_attack_high > 1) && (sta->beacon_attack > 1) )			
				sa << "\e[31mLikely Attack\e[0m (var:" << sta->longVar << ", beacons:" << sta->beacon_ave << "[> 1000/" << sta->beacon_int << "] )";
			// long variance over 10 for two or more seconds and beacon rate above normal   (weak attack)
			else if ( (sta->var_attack_low > 1) && (sta->beacon_attack > 1) )		
				sa << "\e[31mPossible Attack\e[0m (var:" << sta->longVar << ", beacons:" << sta->beacon_ave << "[> 1000/" << sta->beacon_int << "] )";
			// spike in short variance in last second and beacon rate above normal
			else if ( (sta->shortVar_flag == 1) && (sta->beacon_attack >= 1) )		
				sa << "\e[31mLooks like an attack is starting\e[0m (shortVar:" << sta->shortVar << ", beacons:" << "[> 1000/" << sta->beacon_int << "] )";
			
			sa << "\n";
			}		
	}

	if (badcrc > 0) {
		int total = badcrc + goodcrc;
		if (total > 0) {
			double fer = (double) badcrc / (double) total;
			int len = sprintf(sa.reserve(20), "\nFER: %d / %d = %lf", badcrc, total, fer);
			sa.adjust_length((int) len);
		} else { sa << "No packets recieved!"; }
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



void RogueDetect::getStats (StationList &l) {
	
	int error = 1; // beacon per second error
	
	for (StationList::iterator sta = l.begin(); sta != l.end(); ++sta) {

		debug << "\n" << sta->mac->unparse().c_str();
		getAverage(*sta, 100);
		getLongVariance(*sta, 100);
		getEWMA(*sta);

		if (sta->past_beacons.size() >= window) {
			sta->past_beacons.pop_front();
		}
		// put new rssi in array
		sta->past_beacons.push_back(sta->beacon_rate);

		getBeaconAverage(*sta, 3);

		// beacon rate attack detector
		if ( sta->beacon_ave > ( int(1000/sta->beacon_int) + error )) {
			if (sta->beacon_attack >= 1)
				sta->beacon_attack++;
			else
				sta->beacon_attack = 1;
		}
		else {
			sta->beacon_attack = 0;
		}

		// variance attack detector
		if (sta->longVar > 20) {
			if (sta->var_attack_high >= 1) {
				sta->var_attack_high++;
			}
			else {
				sta->var_attack_high = 1;
			}
		}
		else if (sta->longVar > 10) {
			if (sta->var_attack_low >= 1) {
				sta->var_attack_low++;
			}
			else {
				sta->var_attack_low = 1;
			}

		}
		else {
			sta->var_attack_high = 0;
			sta->var_attack_low = 0;
		}

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

void RogueDetect::getBeaconAverage(station &sta, int samples) {

	sta.beacon_ave = 0;
	if (sta.past_beacons.size() < samples)
		samples = sta.past_beacons.size();

	int start = sta.past_beacons.size() - samples;

	debug << "\ngetBeaconAverage: ";

	if (!sta.past_beacons.empty()) {
		for(int i = start; i < sta.past_beacons.size(); i++) {
			debug << sta.past_beacons.at(i) << " + ";
			sta.beacon_ave += sta.past_beacons.at(i);
		}
		sta.beacon_ave = sta.beacon_ave / samples;
	}
	else {
		sta.beacon_ave = sta.beacon_rate;
	}
	debug << " -> BeaconAverage = " << sta.beacon_ave;
}

void RogueDetect::getLongVariance(station &sta, int samples) {

	sta.longVar = 0;
	if (sta.past_packets.size() < samples)
		samples = sta.past_packets.size();

	int start = sta.past_packets.size() - samples;
	debug << "\ngetLongVariance: ";

	if (!sta.past_packets.empty()) {
		for(int j = start; j < sta.past_packets.size(); j++) {
			sta.longVar += (sta.past_packets.at(j) - sta.ave) * (sta.past_packets.at(j) - sta.ave);
			debug << sta.longVar << ", ";
		}
		sta.longVar = sta.longVar / samples;
	}
	else {
		sta.longVar = 0;
	}
	debug << " -> variance = " << sta.longVar;

}

void RogueDetect::getShortVariance(station &sta, int samples) {

	sta.shortVar = 0;
	if (sta.past_packets.size() < samples)
		samples = sta.past_packets.size();

	int start = sta.past_packets.size() - samples;

	if (int(sta.ave) == 0) { 
		sta.ave = sta.past_packets.at(start);
	}

	if (!sta.past_packets.empty()) {
		for(int j = start; j < sta.past_packets.size(); j++) {
			sta.shortVar += (sta.past_packets.at(j) - sta.ave) * (sta.past_packets.at(j) - sta.ave);
		}
		sta.shortVar = sta.shortVar / samples;
	}
	else {
		sta.shortVar = 0;
	}

	// if high raise flag
	if (sta.shortVar > 50)
		sta.shortVar_flag = 1;
	else
		sta.shortVar_flag = 0;
}

void RogueDetect::getEWMA(station &sta) {

	if(!sta.past_packets.empty()) {
		sta._ewma.assign( uint64_t (sta.past_packets.at(0) << sta._ewma.scale()) );
		for(int i = 1; i < sta.past_packets.size(); i++) {
			sta._ewma.update(sta.past_packets.at(i));
		}
	}
	else {
		sta._ewma.update(0);
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
	struct click_wifi_extra *ceha = WIFI_EXTRA_ANNO(p);

	struct station *sta = new station;
		
	int is_beacon = 0,  is_data = 0, salvageable = 0;
	uint8_t *ptr;

	int type = w->i_fc[0] & WIFI_FC0_TYPE_MASK;
	int subtype = w->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;
	int failed_crc = 0;	

	// Check failed errors

	if (ceha->flags & WIFI_EXTRA_RX_MORE) {				// No CRC		
		failed_crc = 1;
		badcrc++;
		p->kill();
		goto end;
	} else {
		if (ceha->flags & WIFI_EXTRA_RX_ERR) {			// Failed CRC
			if (subtype ==  WIFI_FC0_SUBTYPE_BEACON) {	// try save packet
				salvageable = 1;				
			} else {
				failed_crc = 1;
				badcrc++;
				p->kill();
				goto end;
			}	
		} else {
			goodcrc++;
		}
	}

	// Check DS Status

	switch (w->i_fc[1] & WIFI_FC1_DIR_MASK) {
		case WIFI_FC1_DIR_NODS:
			sta->dst = new EtherAddress(w->i_addr1);
			sta->src = new EtherAddress(w->i_addr2);
			sta->mac = new EtherAddress(w->i_addr3);
			dir << "NoDS  ";
			break;
		/*case WIFI_FC1_DIR_TODS:
			sta->mac = new EtherAddress(w->i_addr1);	// not interested in ToDS
			sta->dst = new EtherAddress(w->i_addr1);	// as gives bad results
			sta->src = new EtherAddress(w->i_addr2);	// using two wireless cards 
			dir << "ToDS  ";
			break;*/
		case WIFI_FC1_DIR_FROMDS:
			sta->mac = new EtherAddress(w->i_addr2);
			sta->dst = new EtherAddress(w->i_addr1);
			sta->src = new EtherAddress(w->i_addr2);
			dir << "FromDS";
			break;
		case WIFI_FC1_DIR_DSTODS:
			sta->mac = new EtherAddress(w->i_addr3);
			sta->dst = new EtherAddress(w->i_addr1);
			sta->src = new EtherAddress(w->i_addr2);
			dir << "DStoDS";
			break;
		default:
			goto push;
	}

	if (salvageable) {
		struct station *saved = lookup(*sta, _sta_list);
		if (saved) {
			saved->salvaged++;					// only taking beacon rate
		}
		p->kill();
		goto end;
	}

		
	switch (type) {								
		case WIFI_FC0_TYPE_DATA:
			is_data = 1;
			break;
		case WIFI_FC0_TYPE_MGT:
			if (subtype == WIFI_FC0_SUBTYPE_BEACON) {
				if (sta->dst->is_broadcast()) {
					is_beacon = 1;	

					ptr = ( (uint8_t *) (w+1) ) + 8;	// get beacon interval (ms)
					sta->beacon_int = le16_to_cpu(*(uint16_t *) ptr);	
				}
			} else {
				goto push;
			}
			break;
		default:
			goto push; // pass through other types
	}

	if(!sta->beacon_int) {
		sta->beacon_int = 0;
	}

	// interrogate packets	
	sta->rssi = ceha->rssi;						// get rssi
	if (sta->rssi > 200)						// check for negative SNR | bug?
		sta->rssi = 0;

	if (!_sta_list.empty()) {					// list not empty, so lookup
		struct station *duplicate = lookup(*sta, _sta_list);
		if (duplicate) {					// if list seen before
			
			duplicate->time->set_now();
			duplicate->rssi = sta->rssi;

			keepTrack(*duplicate);
			getShortVariance(*duplicate, 2);

			if (is_beacon) {
				duplicate->beacon_rate++;
				if (duplicate->mactime) {		// beacon jitter check 
					uint32_t jitter = (ceha->tsft - duplicate->mactime) % 102400;
					if (jitter > 51200)
						jitter = 102400 - jitter;
					duplicate->avg_jitter += jitter;
					duplicate->jitter = jitter;
				}
				duplicate->mactime = (u_int64_t) ceha->tsft;
			}

			if (duplicate->rssi > 50) {
				click_chatter("High RSSI %s: %d", \
						duplicate->mac->unparse_colon().c_str(), duplicate->rssi);
			}

			// time | rssi | shortVariance | Beacon Jitter| longVariance | RSSI EWMA | Beacon Rate
			log << *duplicate->time	<< "\t";
			log <<  duplicate->rssi	<< "\t";
			log <<  duplicate->shortVar  << "\t";

			if (is_beacon && duplicate->jitter > 0)
				log << (double) duplicate->jitter << "\t";
			else
				log << "NaN\t";

			if (duplicate->flag == 1) {			// once a sec print these
				log << duplicate->longVar << "\t";
				log << duplicate->_ewma.unparse() << "\t";
				log << duplicate->beacon_rate << "\t";

				if (duplicate->beacon_rate > 0) {
					duplicate->avg_jitter = duplicate->avg_jitter / duplicate->beacon_rate;
					log << duplicate->avg_jitter << "\t";
				} else {
					duplicate->avg_jitter = 0; 
					log << "NaN\t";
				}
							
				duplicate->flag = 0;
				duplicate->beacon_rate = 0;
			}
			
			
		}
		else {

			sta->salvaged = 0;
			sta->jitter = 0;			

			sta->time = new Timestamp(Timestamp::now());
			sta->first_run = 1;
			sta->shortVar = 0;

			keepTrack(*sta);
			if (is_beacon) {
				sta->beacon_rate = 2;
			} else {
				sta->beacon_rate = 1;
			}

			log << *sta->time << "\t";
			log <<  sta->rssi << "\t";
			log <<  sta->shortVar << "\t";				

			_sta_list.push_back(sta);
		}
	}
	else {					// list is empty so add

		goodcrc = 0;			// first run implied
		badcrc = 0;			// so good time to set globals.
		sta->salvaged = 0;
		sta->jitter = 0;

		sta->time = new Timestamp(Timestamp::now());
		sta->first_run = 1;
		sta->shortVar = 0;

		keepTrack(*sta);
		if (is_beacon) {
			sta->beacon_rate = 2;
		} else {
			sta->beacon_rate = 1;
		}

		log << *sta->time << "\t";
		log <<  sta->rssi << "\t";
		log <<  sta->shortVar << "\t";				

		_sta_list.push_back(sta);
	}		

	log << "\n";
	#if CLICK_USERLEVEL
	logOutput(*sta, log);
	#endif
	
	push:
	output(0).push(p);

	end:
	return;
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


