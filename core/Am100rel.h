#ifndef _Am100rel_h_
#define _Am100rel_h_

#include "AmSipMsg.h"
#include "AmEvent.h"

class AmSipDialog;
class AmSipDialogEventHandler;

struct ProvisionalReplyConfirmedEvent
  : public AmEvent
{
    ProvisionalReplyConfirmedEvent()
      : AmEvent(0)
    {}
};

class Am100rel
{

public:
  /** enable the reliability of provisional replies? */
  enum State {
    REL100_DISABLED=0,
    REL100_SUPPORTED,
    REL100_SUPPORTED_NOT_ANNOUNCED,
    REL100_REQUIRE,
    //REL100_PREFERED, //TODO
    REL100_IGNORED,
    REL100_MAX
  };
  
private:
  State initial_state;
  State uac_state;
  State uas_state;

  unsigned rseq;          // RSeq for next request
  bool rseq_confirmed;    // latest RSeq is confirmed
  unsigned rseq_1st;      // value of first RSeq (init value)

  AmSipDialog* dlg;
  AmSipDialogEventHandler* hdl;

public:
  Am100rel(AmSipDialog* dlg, AmSipDialogEventHandler* hdl);

  void setState(State s) { uac_state = uas_state = initial_state = s; }
  State getInitialState() { return initial_state; }
  State getUacState() { return uac_state; }
  State getUasState() { return uas_state; }

  bool checkReply(AmSipReply& reply);

  int  onRequestIn(const AmSipRequest& req);
  int  onReplyIn(const AmSipReply& reply);
  void onRequestOut(AmSipRequest& req);
  void onReplyOut(AmSipReply& reply);

  void onTimeout(const AmSipRequest& req, const AmSipReply& rpl);
};

#endif
