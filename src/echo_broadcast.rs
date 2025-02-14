
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use crate::participants::{ParticipantCounter, ParticipantList};
use crate::protocol::{
    internal::{SharedChannel, Waitpoint},
    Participant,
};
use crate::protocol::ProtocolError;

/// This structure is essential for the reliable broadcast protocol
/// Send is used in the first phase, Echo in the second, and Ready
/// in the third.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessageType<T> {
    Send(T),
    Echo(T),
    Ready(T),
}

/// A homemade sturcture that allows counting the number of
/// votes gathered during the reliable-broadcast protocol
/// only requiring from votes to have trait PartialEq
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
        self.list.iter().find(|(e, _)| e == item).map(|(_, count)| *count)
    }
}


/// Outputs the necessary Echo-Broadcast thresholds based on the
/// total number of participants.
fn echo_ready_thresholds(n: usize) -> (usize, usize){
    // we should always have n >= 3*threshold + 1
    let mut broadcast_threshold = match n % 3 {
        0 => n/3 - 1,
        _ => (n - (n % 3))/ 3,
    };

    let echo_threshold =  if broadcast_threshold <= 0 {
        broadcast_threshold = 0;
        0
    } else {
        (n+broadcast_threshold)/2
    };
    let ready_threshold = broadcast_threshold;
    (echo_threshold, ready_threshold)
}

/// This reliable broadcast function is the echo-broadcast protocol from the sender side.
/// It broadcasts either true or false and expects that the output of the broadcasts be the same as the input data
/// This function is expected to be applied to ensure either all (honest) nodes succeed a specific protocol or they fail
pub async fn reliable_broadcast_send<T> (
    chan: &SharedChannel,
    wait: Waitpoint,
    participants: &ParticipantList,
    me: &Participant,
    data: T,
) -> MessageType<T>
where T: Serialize + Copy {
    let vote  = MessageType::Send(data);
    let sid = participants.index(me.clone());
    // Send vote to all participants but for myself
    chan.send_many(wait,  &(&sid, &vote)).await;
    // the vote is returned to be taken into consideration as received
    vote
}


/// This reliable broadcast function is the echo-broadcast protocol from the sender receiver side.
/// It broadcasts either true or false and expects that the output of the broadcasts be the same as the input data
/// If vote is Some, then reliable_broadcast_receive_all is expected to be called right after reliable_broadcast_send
pub async fn reliable_broadcast_receive_all<T>(
    chan: &SharedChannel,
    wait: Waitpoint,
    participants: &ParticipantList,
    me: &Participant,
    send_vote: MessageType<T>,
) -> Result<Vec<T>, ProtocolError>
where T:Serialize + Clone + DeserializeOwned + Copy + PartialEq
{
    let n = participants.len();
    let (echo_t, ready_t) = echo_ready_thresholds(n);

    let mut vote_output: Vec<T> = Vec::new();
    // first dimension determines the session
    // second dimension contains the counter for success/failure of the received strings
    let mut fail_success_echo =  vec![CounterList::new(); n];
    let mut fail_success_ready =  vec![CounterList::new(); n];

    // first dimension determines the session
    // second dimension helps prevent duplication: correct processes should deliver at most one message
    let mut seen_echo = vec![ParticipantCounter::new(&participants); n];
    let mut seen_ready = vec![ParticipantCounter::new(&participants); n];

    let mut finish_send = vec![false; n];
    let mut finish_echo = vec![false; n];
    let mut finish_amplification = vec![false; n];
    let mut finish_ready = vec![false; n];

    // since send_many sends to everybody but the sender,
    // we introduce these variable to fake the sender receiving a vote from itself
    let mut send_activated = true;
    let mut echo_activated = false;
    let mut ready_activated = false;

    let mut from = me.clone();
    let mut sid = 0;
    let mut vote = send_vote.clone();
    loop {
        // this function is allowed to return an error and stop the protocol
        // if prepare_vote returns an error, it means that the implementation logic is wrong.
        // if prepare_vote returns false, it means that a party sent a trash message so the loop continues
        if !prepare_vote(
            &mut send_activated,
            &mut echo_activated,
            &mut ready_activated,
            &mut from,
            &mut sid,
            &mut vote,
            chan,
            wait,
            participants,
            me,
            &send_vote,
        ).await? {
            continue;
        }

        match vote {
            // Receive send vote then echo to everybody
            MessageType::Send(data) => {
                // if the sender is not the one identified by the session id (sid)
                // or if the sender have already delivered a MessageType::Send message
                // then skip
                if finish_send[sid] || sid != participants.index(from.clone()){
                    continue;
                }
                // upon receiving a send message, echo it
                chan.send_many(wait, &(&sid, &MessageType::Echo(data))).await;
                finish_send[sid] = true;
                // activate the boolean saying that *me* want to deliver echo
                // to all participants including myself
                echo_activated = true
            },
            // Receive send vote then echo to everybody
            MessageType::Echo(data) => {
                // skip if I received echo message from the sender in a specific session (sid)
                // or if I had already passed to the ready phase in this same session
                if !seen_echo[sid].put(from) || finish_echo[sid]{
                    continue;
                }
                // insert or increment the number of collected echo of a specific vote
                fail_success_echo[sid].insert_or_increase_counter(data);

                // upon gathering strictly more than (n+f)/2 votes
                // for a result, deliver (READY, vote)
                if fail_success_echo[sid].get(&data).unwrap() > echo_t{
                    chan.send_many(wait,   &(&sid, &MessageType::Ready(data))).await;
                    // state that the echo phase for session id (sid) is done
                    finish_echo[sid] = true;
                    // activate the boolean saying that *me* wants to deliver ready
                    // to all participants including myself
                    ready_activated = true;
                }
            },
            MessageType::Ready(data) => {
                // skip if I received echo message from the sender in session sid
                if !seen_ready[sid].put(from) || finish_ready[sid] {
                    continue;
                }

                // insert or increment the number of collected ready of a specific vote
                fail_success_ready[sid].insert_or_increase_counter(data);

                // upon gathering strictly more than f votes
                // and if I haven't already amplified ready vote in session sid then
                // proceed to amplification of the ready message
                if fail_success_ready[sid].get(&data).unwrap() > ready_t && finish_amplification[sid] == false{
                    chan.send_many(wait,  &(&sid, &MessageType::Ready(data))).await;
                    finish_amplification[sid] = true;
                    // activate the boolean saying that *me* wants to deliver ready
                    // to all participants including myself
                    ready_activated = true;
                }
                if fail_success_ready[sid].get(&data).unwrap() > 2*ready_t{
                    // skip all types of messages sent for session sid from now on
                    finish_send[sid] = true;
                    finish_echo[sid] = true;
                    finish_ready[sid] = true;

                    // return an array of data
                    // make a list of data and return them
                    vote_output.push(data);

                    // // fail on first failure
                    // if data == false {
                    //     return Ok(false);
                    // }
                    // // if all the ready slots are set to true
                    // // then all sessions have ended successfully
                    // // we can thus output that the n instances of the broadcast protocols have succeeded
                    if finish_ready.iter().all(|&x| x) {
                        return Ok(vote_output);
                    }
                }
            },
        }
    }
}

pub async fn do_broadcast <T>(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: &Participant,
    data: T,
) ->  Result<Vec<T>, ProtocolError>
where T:Serialize + Clone + DeserializeOwned + Copy + PartialEq
{
    let wait_broadcast = chan.next_waitpoint();
    let send_vote = reliable_broadcast_send(&chan, wait_broadcast, &participants, &me, data).await;
    let vote_list = reliable_broadcast_receive_all(&chan, wait_broadcast, &participants, &me, send_vote).await?;
    Ok(vote_list)
}

/// Prepares a vote either received in a communication
/// or simulates the reception of a vote when running send_many
/// (function send_many does not seem to deliver a message to the sender
/// which, if not taken care of, could cause problems in BFT vote count)
async fn prepare_vote<T>(
    send_activated: &mut bool,
    echo_activated: &mut bool,
    ready_activated: &mut bool,
    from: &mut Participant,
    sid: &mut usize,
    vote: &mut MessageType<T>,
    chan: &SharedChannel,
    wait: Waitpoint,
    participants: &ParticipantList,
    me: &Participant,
    send_vote: &MessageType<T>,
) -> Result<bool, ProtocolError>
where T: DeserializeOwned + Clone + Copy {
    if *send_activated {
        *send_activated = false;
        match send_vote {
            MessageType::Send(data) => {
                *from = me.clone();
                *sid = participants.index(me.clone());
                *vote = MessageType::Send(*data);
            }
            _ => return Err(ProtocolError::AssertionFailed(
                        format!("The function reliable_broadcast_receive_all is expected to be called reliable_broadcast_send {me:?}")
                        )),
        }
    } else if *echo_activated {
        *echo_activated = false;
        *from = me.clone();
        *vote = match vote {
            MessageType::Send(data) =>  MessageType::Echo(*data),
            _ =>  return Err(ProtocolError::AssertionFailed(
                format!("Message is not of type Send! Exiting {me:?}.")
                )),
        }
    } else if *ready_activated {
        *ready_activated = false;
        *from = me.clone();
        *vote = match vote {
            MessageType::Echo(data) =>  MessageType::Ready(*data),
            MessageType::Ready(data) => MessageType::Ready(*data),
            _ => return Err(ProtocolError::AssertionFailed(
                format!("Message is neither of type Echo nor Ready (amplify) ! Exiting {me:?}.")
                )),
        }
    } else {
        // The recv should be failure-free
        // This translates to ignoring the received message when deemed wrong
        // types of the received answers are (Participant, (usize, MessageType))
        (*from, (*sid, *vote)) = match chan.recv(wait).await {
            Ok(value) => value,
            _ => return Ok(false),
        };
    }
    Ok(true)
}



#[cfg(test)]
mod test {
    use super::*;
    use crate::protocol::internal::{make_protocol, Context};
    use std::error::Error;
    use crate::protocol::{run_protocol, Protocol};
    use crate::protocol::ProtocolError;

    /// This function is similar to do_broadcast except it is tailored to
    /// consume the inputs instead of borrowing and become suitable for make_protocol
    /// function
    pub async fn do_broadcast_consume(
        mut chan: SharedChannel,
        participants: ParticipantList,
        me: Participant,
        data: bool,
    ) ->  Result<Vec<bool>, ProtocolError>
    {
        let wait_broadcast = chan.next_waitpoint();
        let send_vote = reliable_broadcast_send(&chan, wait_broadcast, &participants, &me, data).await;
        let vote_list = reliable_broadcast_receive_all(&chan, wait_broadcast, &participants, &me, send_vote).await?;
        Ok(vote_list)
    }

    #[allow(clippy::type_complexity)]
    pub fn do_broadcast_honest(
        participants: &[Participant],
        me: Participant,
        data: bool,
    ) -> Result<impl Protocol<Output = Vec<bool>> , ProtocolError> {
        let participants = ParticipantList::new(participants).unwrap();

        if !participants.contains(me){
            return Err(ProtocolError::AssertionFailed(format!("Does not contain me")))
        }
        let ctx = Context::new();
        let chan = ctx.shared_channel();
        let fut = do_broadcast_consume(chan, participants, me, data);

        Ok(make_protocol(ctx, fut))
    }

    /// All participants are assumed to be honest here
    fn broadcast_honest(
        participants: &[Participant],
        votes: &[bool]
    ) -> Result<Vec<(Participant, Vec<bool>)>, Box<dyn Error>> {

        assert_eq!(participants.len(), votes.len());

        let mut protocols: Vec<(
            Participant,
            Box<dyn Protocol<Output = Vec<bool>>>
        )> = Vec::with_capacity(participants.len());


        for (p,b) in participants.iter().zip(votes.iter()) {
            let protocol = do_broadcast_honest(participants, *p, *b)?;
            protocols.push((*p, Box::new(protocol)));
        }

        let result = run_protocol(protocols)?;
        Ok(result)
    }

    #[test]
    fn test_five_honest_participants()
    -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
            Participant::from(4u32),
        ];

        let mut votes = vec![
            true,
            true,
            true,
            true,
            true
        ];

        // change everytime a party voting false
        for i in  0.. votes.len() {
            let result = broadcast_honest(&participants, &votes)?;
            for (_,vec_b) in result.iter(){
                let false_count = vec_b.iter().filter(|&&b| !b).count();
                assert_eq!(false_count, i);
            }
            votes[i] = false;
        }

        Ok(())
    }
}