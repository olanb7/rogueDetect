FromDevice(ath0) -> RadiotapDecap() -> RogueDetect() -> Discard;
//		 -> mon_cl :: Classifier(0/08%0c 1/01%03,	// data
//					 0/00%0c		// mgt
//					);
//		
//mon_cl [0] -> Discard;
//mon_cl [1] -> mgt_cl :: Classifier(0/80%f0);	// beacon

//mgt_cl[] -> RogueDetect() -> Discard;
