FromDevice(ath0) -> RadiotapDecap()
//-> PrintWifi() -> Discard; 
-> RogueDetect() -> Discard;

//-> wifi_cl :: Classifier (0/04%0c,
//                          -);
//
//wifi_cl [0] -> Discard;
//wifi_cl [1] -> probe_cl :: Classifier (0/40%f0,
//					  -);
//probe_cl [0] -> Discard; //ctl
//probe_cl [1] -> RogueDetect() -> Discard;


//wifi_cl [1] -> mgt_cl :: Classifier(0/00%f0, //assoc req
//				    0/10%f0, //assoc resp
//				    0/40%f0, //probe req
//				    0/50%f0, //probe resp
//				    0/80%f0, //beacon
//				    0/a0%f0, //disassoc
//				    0/b0%f0, //disassoc
//				    );
//


