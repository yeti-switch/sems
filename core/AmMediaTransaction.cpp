#include "AmMediaTransaction.h"
#include "AmSession.h"
#include "AmRtpStream.h"
#include "AmRtpAudio.h"
#include "AmMediaEndpoint.h"

AmMediaTransaction::AmMediaTransaction(AmSession *sess, const AmSdp &local_sdp)
    : session(sess)
    , prev_local_sdp(local_sdp)
{
}

AmMediaTransaction::~AmMediaTransaction()
{
    // dropped without commit/rollback
    for (auto &b : bindings)
        b.first->clearPendingEndpoint();
}

AmMediaEndpoint *AmMediaTransaction::addEndpoint(AmMediaEndpoint *ep)
{
    new_endpoints.emplace_back(ep);
    return ep;
}

AmRtpAudio *AmMediaTransaction::addStream(AmRtpAudio *s)
{
    staged_slots.push_back({ std::unique_ptr<AmRtpAudio>(s), MT_NONE, TP_NONE, s->getSdpMediaIndex() });
    return s;
}

void AmMediaTransaction::addEmptySlot(MediaType type, TransProt transport, int media_idx)
{
    staged_slots.push_back({ nullptr, type, transport, media_idx });
}

void AmMediaTransaction::bind(AmRtpStream *stream, AmMediaEndpoint *endpoint)
{
    bindings[stream] = endpoint;
    stream->setPendingEndpoint(endpoint); // SDP is built from the staged endpoint until commit
}

void AmMediaTransaction::forEachStaged(const std::function<void(AmRtpAudio *, MediaType, TransProt)> &fn)
{
    for (auto &slot : staged_slots) {
        if (slot.stream)
            fn(slot.stream.get(), slot.stream->getMediaType(), slot.stream->getTransport());
        else
            fn(nullptr, slot.type, slot.transport);
    }
}

AmRtpAudio *AmMediaTransaction::getStream(int media_idx) const
{
    for (auto &slot : staged_slots)
        if (slot.stream && slot.stream->getSdpMediaIndex() == media_idx)
            return slot.stream.get();
    return nullptr;
}

bool AmMediaTransaction::hasSlotAt(int media_idx) const
{
    for (auto &slot : staged_slots)
        if (slot.media_idx == media_idx)
            return true;
    return false;
}

void AmMediaTransaction::commit()
{
    // same-stream endpoint swap: re-point each stream to its staged endpoint (the old one stays in the
    // session pool until the session ends - in a bundle the shared endpoint needs guarding, TODO(C1))
    for (auto &b : bindings)
        b.first->setEndpoint(b.second);
    bindings.clear();
    for (auto &ep : new_endpoints)
        session->addMediaEndpoint(ep.release()); // staged endpoints handed to the session pool
    new_endpoints.clear();

    for (auto &h : handoffs) {
        h.second->setEndpoint(h.first->getEndpoint());
        h.first->releaseEndpoint();
    }
    handoffs.clear();

    for (auto &slot : staged_slots) {
        if (slot.stream)
            session->addRtpStream(slot.stream.release());
        else
            session->addEmptyRtpSlot(slot.type, slot.transport);
    }
    staged_slots.clear();

    disabled_streams.clear();
}

void AmMediaTransaction::rollback(bool send_reinvite)
{
    // the live binding was never touched - just drop the staged objects
    for (auto &b : bindings)
        b.first->clearPendingEndpoint();
    bindings.clear();
    new_endpoints.clear(); // free staged endpoints

    // the endpoint was never moved (only borrowed for the offer): drop the recipient's pending view;
    // the donor keeps its endpoint and its RX (it was never stopped)
    for (auto &h : handoffs)
        h.second->clearPendingEndpoint();
    handoffs.clear();

    staged_slots.clear();

    for (auto *s : disabled_streams)
        s->setDisabled(false);
    disabled_streams.clear();

    // recovery original transport
    for (size_t i = 0; i < prev_local_sdp.media.size(); i++)
        if (AmRtpStream *s = session->RTPStream((unsigned)i))
            s->setTransport(prev_local_sdp.media[i].transport);

    session->restoreMedia(prev_local_sdp, send_reinvite);
}
