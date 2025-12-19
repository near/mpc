// # TODO(#122): remove this exception
#![allow(clippy::indexing_slicing)]

use crate::participants::{ParticipantCounter, ParticipantList, ParticipantMap};
use crate::protocol::ProtocolError;
use crate::protocol::{
    internal::{SharedChannel, Waitpoint},
    Participant,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// This structure is essential for the reliable broadcast protocol
/// Send is used in the first phase, Echo in the second, and Ready
/// in the third.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType<T> {
    Send(T),
    Echo(T),
    Ready(T),
}

/// A homemade sturcture that allows counting the number of
/// votes gathered during the reliable-broadcast protocol
/// only requiring from votes to have trait `PartialEq`
#[derive(Clone)]
struct CounterList<T> {
    list: Vec<(T, usize)>,
}

impl<T: PartialEq> CounterList<T> {
    fn new() -> Self {
        Self { list: Vec::new() }
    }

    fn insert_or_increase_counter(&mut self, item: T) {
        if let Some((_, count)) = self.list.iter_mut().find(|(e, _)| *e == item) {
            *count += 1;
        } else {
            self.list.push((item, 1));
        }
    }

    fn get(&self, item: &T) -> Option<usize> {
        self.list
            .iter()
            .find(|(e, _)| e == item)
            .map(|(_, count)| *count)
    }

    fn get_sum_counters(&self) -> usize {
        let mut sum = 0;
        for (_, cnt) in &self.list {
            sum += cnt;
        }
        sum
    }

    fn iter(&self) -> std::slice::Iter<'_, (T, usize)> {
        self.list.iter()
    }
}

/// Outputs the necessary Echo-Broadcast thresholds based on the
/// total number of participants. The  threshold in echo-broadcast
/// should be exceeded to continue with the next phase (it is not
/// sufficient to only hit the threshold but this should be exceeded).
/// The threshold are taken from the book:
/// "Introduction to Reliable and Secure Distributed Programming,
/// by C. Cachin, R. Guerraoui, and L. Rodrigues"
fn echo_ready_thresholds(n: usize) -> (usize, usize) {
    // case where no malicious parties are assumed: when n <= 3/
    // In this case the echo and ready thresholds are both 0
    // later we compare if we have collected more votes than these thresholds
    if n <= 3 {
        return (0, 0);
    }
    // we should always have n >= 3*threshold + 1
    let broadcast_threshold = (n - 1) / 3;
    let echo_threshold = usize::midpoint(n, broadcast_threshold);
    (echo_threshold, broadcast_threshold)
}

/// This reliable broadcast function is the echo-broadcast protocol from the sender side.
/// It broadcasts some data in a vote
pub fn reliable_broadcast_send<T>(
    chan: &SharedChannel,
    wait: Waitpoint,
    participants: &ParticipantList,
    me: Participant,
    data: T,
) -> Result<MessageType<T>, ProtocolError>
where
    T: Serialize,
{
    let vote = MessageType::Send(data);
    let sid = participants.index(me)?;
    // Send vote to all participants but for myself
    chan.send_many(wait, &(&sid, &vote))?;
    // the vote is returned to be taken into consideration as received
    Ok(vote)
}

/// This reliable broadcast function is the echo-broadcast protocol from the sender side.
///
/// It broadcasts a vote of type `MessageType::Send` and expects that the output
/// of the broadcasts be the same as the input vote.
/// `Reliable_broadcast_receive_all` is expected to be called right after `reliable_broadcast_send`.
#[allow(clippy::too_many_lines)]
pub async fn reliable_broadcast_receive_all<'a, T>(
    chan: &SharedChannel,
    wait: Waitpoint,
    participants: &'a ParticipantList,
    me: Participant,
    send_vote: MessageType<T>,
) -> Result<ParticipantMap<'a, T>, ProtocolError>
where
    T: Serialize + Clone + DeserializeOwned + PartialEq,
{
    let n = participants.len();
    let (echo_t, ready_t) = echo_ready_thresholds(n);

    let mut vote_output = ParticipantMap::new(participants);

    // first dimension determines the session
    // second dimension contains the counter for the received data
    let mut data_echo = vec![CounterList::new(); n];
    let mut data_ready = vec![CounterList::new(); n];

    // first dimension determines the session
    // second dimension helps prevent duplication: correct processes should deliver at most one message
    let mut seen_echo = vec![ParticipantCounter::new(participants); n];
    let mut seen_ready = vec![ParticipantCounter::new(participants); n];

    let mut finish_send = vec![false; n];
    let mut finish_echo = vec![false; n];
    let mut finish_amplification = vec![false; n];
    let mut finish_ready = vec![false; n];

    // receive simulated vote
    let mut from = me;
    let mut sid = participants.index(me)?;
    let mut vote = match send_vote {
        MessageType::Send(_) => send_vote.clone(),
        _ => {
            return Err(ProtocolError::AssertionFailed(
                "Function
            reliable_broadcast_receive_all MUST take a vote of
            type send_vote as input"
                    .to_string(),
            ))
        }
    };
    let mut is_simulated_vote = true;

    loop {
        // Am I handling a simulated vote sent by me to myself?
        if !is_simulated_vote {
            // The recv should be failure-free
            // This translates to ignoring the received message when deemed wrong
            // types of the received answers are (Participant, (usize, MessageType))
            match chan.recv(wait).await {
                Ok(value) => (from, (sid, vote)) = value,
                _ => continue,
            };
        }

        is_simulated_vote = false;

        if sid >= n {
            continue;
        }

        match vote.clone() {
            // Receive send vote then echo to everybody
            MessageType::Send(data) => {
                // If the sender is not the one identified by the session id (sid)
                // or if the sender have already delivered a MessageType::Send message
                // then skip.
                // The second condition prevents a malicious party starting the protocol
                // on behalf on somebody else
                if finish_send[sid] || sid != participants.index(from)? {
                    continue;
                }
                vote = MessageType::Echo(data);
                // upon receiving a send message, echo it
                chan.send_many(wait, &(&sid, &vote))?;
                finish_send[sid] = true;

                // simulate an echo vote sent by me
                is_simulated_vote = true;
                from = me;
            }
            // Receive send vote then echo to everybody
            MessageType::Echo(data) => {
                // skip if I received echo message from the sender in a specific session (sid)
                // or if I had already passed to the ready phase in this same session
                if !seen_echo[sid].put(from) || finish_echo[sid] {
                    continue;
                }
                // insert or increment the number of collected echo of a specific vote
                data_echo[sid].insert_or_increase_counter(data.clone());

                // upon gathering strictly more than (n+f)/2 votes
                // for a result, deliver Ready.
                if data_echo[sid].get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > echo_t
                {
                    vote = MessageType::Ready(data);
                    chan.send_many(wait, &(&sid, &vote))?;
                    // state that the echo phase for session id (sid) is done
                    finish_echo[sid] = true;

                    // simulate a ready vote sent by me
                    is_simulated_vote = true;
                    from = me;
                }
                // suppose you receive not enough echo votes but the amount of votes
                // left to receive is not sufficient to proceed to the ready phase
                // then deduce that the sender is malicious and stop
                // this is better than letting the timeout stop the process.
                // This check has to be done after counting the simulated value.
                else if !finish_amplification[sid] {
                    // calculate the total number of echos already collected
                    let received_echo_cnt = data_echo[sid].get_sum_counters();
                    // calculate the number of echo to be received
                    let non_received_echo_cnt = n - received_echo_cnt;
                    // iterate over the data_echo[sid] array
                    let mut is_enough = false;
                    for (_, cnt) in data_echo[sid].iter() {
                        // verify whether there is enough votes in at
                        // least one slot to exceed the threshold
                        if cnt + non_received_echo_cnt > echo_t {
                            is_enough = true;
                            break;
                        }
                    }

                    // if not enough echo votes left for hitting the threshold
                    // then we know that the sender is malicious
                    if !is_enough {
                        return Err(ProtocolError::AssertionFailed(format!(
                            "The original sender in session {sid:?} is malicious! Could not collect enough echo votes to meet the threshold"
                        )));
                    }
                }
            }
            MessageType::Ready(data) => {
                // skip if I received ready message from the sender in session sid
                if !seen_ready[sid].put(from) || finish_ready[sid] {
                    continue;
                }

                // insert or increment the number of collected ready of a specific vote
                data_ready[sid].insert_or_increase_counter(data.clone());

                // upon gathering strictly more than f votes
                // and if I haven't already amplified ready vote in session sid then
                // proceed to amplification of the ready message
                if data_ready[sid].get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > ready_t
                    && !finish_amplification[sid]
                {
                    vote = MessageType::Ready(data.clone());
                    chan.send_many(wait, &(&sid, &vote))?;
                    finish_amplification[sid] = true;

                    // simulate a ready vote sent by me
                    is_simulated_vote = true;
                    from = me;
                }
                if data_ready[sid].get(&data).ok_or_else(|| {
                    ProtocolError::Other("Missing element in CounterList".to_string())
                })? > 2 * ready_t
                {
                    // skip all types of messages sent for session sid from now on
                    finish_send[sid] = true;
                    finish_echo[sid] = true;
                    finish_ready[sid] = true;

                    // return a map of participant data
                    let p = participants
                        .get_participant(sid)
                        .ok_or_else(|| ProtocolError::Other("Missing participant".to_string()))?;
                    // make a list of data and return them
                    vote_output.put(p, data.clone());

                    // Output error if the received vote after broadcast is not
                    // the same as the one originally sent
                    if sid == participants.index(me)? && MessageType::Send(data) != send_vote {
                        return Err(ProtocolError::AssertionFailed(
                            "Too many malicious parties, way above the assumed threshold:
                            The message output after the broadcast protocol is not the same as
                            the one originally sent by me"
                                .to_string(),
                        ));
                    }

                    // if all the ready slots are set to true
                    // then all sessions have ended successfully
                    // we can thus output that the n instances of the broadcast protocols have succeeded
                    if finish_ready.iter().all(|&x| x) {
                        return Ok(vote_output);
                    }
                }
            }
        }
    }
}

/// The reliable echo-broadcast protocol that party me is supposed
/// to run with all the other parties
pub async fn do_broadcast<'a, T>(
    chan: &mut SharedChannel,
    participants: &'a ParticipantList,
    me: Participant,
    data: T,
) -> Result<ParticipantMap<'a, T>, ProtocolError>
where
    T: Serialize + Clone + DeserializeOwned + PartialEq,
{
    let wait_broadcast = chan.next_waitpoint();
    let send_vote = reliable_broadcast_send(chan, wait_broadcast, participants, me, data)?;
    let vote_list =
        reliable_broadcast_receive_all(chan, wait_broadcast, participants, me, send_vote).await?;
    Ok(vote_list)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::protocol::internal::{make_protocol, Comms};
    use crate::protocol::{Protocol, ProtocolError};
    use crate::test_utils::{generate_participants, run_protocol};

    /// This function is similar to `do_broadcast` except it is tailored to
    /// consume the inputs instead of borrowing and become suitable for `make_protocol`
    /// function
    async fn do_broadcast_consume(
        mut chan: SharedChannel,
        participants: ParticipantList,
        me: Participant,
        data: bool,
    ) -> Result<Vec<bool>, ProtocolError> {
        let wait_broadcast = chan.next_waitpoint();
        let send_vote = reliable_broadcast_send(&chan, wait_broadcast, &participants, me, data)?;
        let vote_list =
            reliable_broadcast_receive_all(&chan, wait_broadcast, &participants, me, send_vote)
                .await?;
        let vote_list = vote_list.into_vec_or_none().unwrap();
        Ok(vote_list)
    }

    fn do_broadcast_honest(
        participants: &[Participant],
        me: Participant,
        data: bool,
    ) -> Result<impl Protocol<Output = Vec<bool>>, ProtocolError> {
        let participants = ParticipantList::new(participants).unwrap();

        if !participants.contains(me) {
            return Err(ProtocolError::AssertionFailed(
                "Does not contain me".to_string(),
            ));
        }
        let comms = Comms::new();
        let chan = comms.shared_channel();
        let fut = do_broadcast_consume(chan, participants, me, data);

        Ok(make_protocol(comms, fut))
    }

    /// All participants are assumed to be honest here
    fn broadcast_honest(
        participants: &[Participant],
        votes: &[bool],
    ) -> Vec<(Participant, Vec<bool>)> {
        assert_eq!(participants.len(), votes.len());

        let mut protocols: Vec<(_, Box<dyn Protocol<Output = Vec<bool>>>)> =
            Vec::with_capacity(participants.len());

        for (p, b) in participants.iter().zip(votes.iter()) {
            let protocol = do_broadcast_honest(participants, *p, *b).unwrap();
            protocols.push((*p, Box::new(protocol)));
        }

        run_protocol(protocols).unwrap()
    }

    async fn do_broadcast_dishonest_consume_version_1(
        mut chan: SharedChannel,
        participants: ParticipantList,
        me: Participant,
    ) -> Result<Vec<bool>, ProtocolError> {
        let wait_broadcast = chan.next_waitpoint();
        let sid = participants.index(me)?;

        // malicious reliable broadcast send
        let vote_true = MessageType::Send(true);
        let vote_false = MessageType::Send(false);

        for (cnt, p) in participants.others(me).enumerate() {
            if cnt >= participants.len() / 2 {
                chan.send_private(wait_broadcast, p, &(&sid, &vote_false))?;
            } else {
                chan.send_private(wait_broadcast, p, &(&sid, &vote_true))?;
            }
        }

        let vote_list =
            reliable_broadcast_receive_all(&chan, wait_broadcast, &participants, me, vote_false)
                .await?;
        let vote_list = vote_list.into_vec_or_none().unwrap();
        Ok(vote_list)
    }

    async fn do_broadcast_dishonest_consume_version_2(
        mut chan: SharedChannel,
        participants: ParticipantList,
        me: Participant,
    ) -> Result<Vec<bool>, ProtocolError> {
        let wait_broadcast = chan.next_waitpoint();
        let sid = participants.index(me)?;

        // malicious reliable broadcast send
        let vote_true = MessageType::Send(true);
        let vote_false = MessageType::Send(false);

        for (cnt, p) in participants.others(me).enumerate() {
            if cnt >= participants.len() / 2 {
                chan.send_private(wait_broadcast, p, &(&sid, &vote_false))?;
            } else {
                chan.send_private(wait_broadcast, p, &(&sid, &vote_true))?;
            }
        }

        let vote_list =
            reliable_broadcast_receive_all(&chan, wait_broadcast, &participants, me, vote_true)
                .await?;
        let vote_list = vote_list.into_vec_or_none().unwrap();
        Ok(vote_list)
    }

    fn do_broadcast_dishonest<F, Fut>(
        participants: &[Participant],
        me: Participant,
        do_broadcast_dishonest_consume: F,
    ) -> Result<impl Protocol<Output = Vec<bool>>, ProtocolError>
    where
        F: FnOnce(SharedChannel, ParticipantList, Participant) -> Fut,
        Fut: futures::Future<Output = Result<Vec<bool>, ProtocolError>> + Send + 'static,
    {
        // the idea is that the dishonest party is going to send one 2 true and two false
        let participants = ParticipantList::new(participants).unwrap();

        if !participants.contains(me) {
            return Err(ProtocolError::AssertionFailed(
                "Does not contain me".to_string(),
            ));
        }
        let comms = Comms::new();
        let chan = comms.shared_channel();

        let fut = do_broadcast_dishonest_consume(chan, participants, me);

        Ok(make_protocol(comms, fut))
    }

    // This is needed because this function must fail in test `test_three_honest_one_dihonest`
    #[allow(clippy::panic_in_result_fn)]
    fn broadcast_dishonest<F, Fut>(
        honest_participants: &[Participant],
        dishonest_participant: Participant,
        honest_votes: &[bool],
        do_broadcast_dishonest_consume: F,
    ) -> Result<Vec<(Participant, Vec<bool>)>, ProtocolError>
    where
        F: FnOnce(SharedChannel, ParticipantList, Participant) -> Fut + 'static,
        Fut: futures::Future<Output = Result<Vec<bool>, ProtocolError>> + Send + 'static,
    {
        assert_eq!(honest_participants.len(), honest_votes.len());

        let mut participants = honest_participants.to_vec();
        participants.push(dishonest_participant);

        let mut protocols: Vec<(_, Box<dyn Protocol<Output = Vec<bool>>>)> =
            Vec::with_capacity(participants.len());

        // we run the protocol for all honest parties
        for (p, b) in honest_participants.iter().zip(honest_votes.iter()) {
            let protocol = do_broadcast_honest(&participants, *p, *b).unwrap();
            protocols.push((*p, Box::new(protocol)));
        }

        // we run the protocol for the dishonest party
        let protocol = do_broadcast_dishonest(
            &participants,
            dishonest_participant,
            do_broadcast_dishonest_consume,
        )
        .unwrap();

        protocols.push((dishonest_participant, Box::new(protocol)));

        run_protocol(protocols)
    }

    #[test]
    fn test_five_honest_participants() {
        let participants = generate_participants(5);

        let mut votes = vec![true, true, true, true, true];

        // change everytime a party voting false
        for i in 0..votes.len() {
            let result = broadcast_honest(&participants, &votes);
            for (_, vec_b) in &result {
                let false_count = vec_b.iter().filter(|&&b| !b).count();
                assert_eq!(false_count, i);
            }
            votes[i] = false;
        }
    }

    #[test]
    fn test_three_honest_one_dihonest() {
        // threshold is assumed to be n >= 3*threshold + 1
        let honest_participants = generate_participants(3);

        let dishonest_participant = Participant::from(3u32);

        let honest_votes = vec![true, true, true];

        // version 1
        let result = broadcast_dishonest(
            &honest_participants,
            dishonest_participant,
            &honest_votes,
            do_broadcast_dishonest_consume_version_1,
        );
        assert_eq!(result, Err(ProtocolError::AssertionFailed("The original sender in session 3 is malicious! Could not collect enough echo votes to meet the threshold".to_string())));
        // version 2
        let result = broadcast_dishonest(
            &honest_participants,
            dishonest_participant,
            &honest_votes,
            do_broadcast_dishonest_consume_version_2,
        )
        .unwrap();

        for (_, vec_b) in &result {
            let false_count = vec_b.iter().filter(|&&b| !b).count();
            assert_eq!(false_count, 0);
        }
    }

    async fn do_broadcast_dishonest_consume_bad_sid(
        mut chan: SharedChannel,
        participants: ParticipantList,
        me: Participant,
    ) -> Result<Vec<bool>, ProtocolError> {
        let wait_broadcast = chan.next_waitpoint();

        // Maliciously craft a message with a bad sid
        let bad_sid = participants.len(); // This is out of bounds
        let vote = MessageType::Send(true);

        // Send this malicious message to all other participants
        chan.send_many(wait_broadcast, &(&bad_sid, &vote))?;

        // The malicious node should also participate honestly to not stall the protocol for other reasons.
        let send_vote = reliable_broadcast_send(&chan, wait_broadcast, &participants, me, false)?;
        let vote_list =
            reliable_broadcast_receive_all(&chan, wait_broadcast, &participants, me, send_vote)
                .await?;
        let vote_list = vote_list.into_vec_or_none().unwrap();
        Ok(vote_list)
    }

    #[test]
    fn test_malicious_sid_ignored() {
        let honest_participants = generate_participants(3);
        let dishonest_participant = Participant::from(3u32);
        let honest_votes = vec![true, true, true];

        // The broadcast_dishonest function returns a Result.
        // If the protocol panics, the test will fail.
        // If it returns Ok, it means the protocol completed.
        let result = broadcast_dishonest(
            &honest_participants,
            dishonest_participant,
            &honest_votes,
            do_broadcast_dishonest_consume_bad_sid,
        );

        // We expect the protocol to complete successfully.
        assert!(result.is_ok());

        let final_votes = result.unwrap();
        // The final votes should not be affected by the malicious message.

        // All participants should have the same view of the votes.
        for (p, v) in final_votes {
            let v_expected = vec![true, true, true, false];
            if p == dishonest_participant {
                // The dishonest participant might have a different view of its own vote
                // depending on when it processes its own message.
                // The important part is that it doesn't panic and that honest nodes agree.
            } else {
                assert_eq!(v, v_expected);
            }
        }
    }
}
