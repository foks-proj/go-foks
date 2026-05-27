# Social Signup Flow

A team owner on a big host might want to invite someone onto the server
and into the team, in one feel swoop. The team owner might have some
"invite credits" on the host that she can bring to bear on this 
flow. As part of the flow, the inviter and the invitee might share
some text messages back and forth, for the purposes of identification.
However, the whole flow must be initiated over a channel that is 
E2EE to begin with, since the messages back and forth cannot
serve as a true PAKE secret. Thus, the flow is: (1) the inviter prepare
an invitation link; (2) sends the link over Signal or Whatsapp; (3)
the invitee acceepts, perhaps sending messages back and forth; and (4)
the inviter brings the invitee into the team via existing inbox 
capability. 

The protocol should work for both users who are already signed up,
and those who are making an account for the first time. There
are some slight changes in the case of the invitee already having
and account: (1) the inviter does not need to use an invite credit;
and (2) the invitee does not need to go through the signup process.
However, the rest of the flow should be similar.

## Signup + Invite Flow

### Setup

- Parties: Alice is the inviter; Bob is the invitee; Alice is an admin of team T
- For Alice:
    - U_A: Alice's UID
    - P_A: Alice's public key (PUK)
- For Bob:
    - U_B: Bob's UID
    - P_B: Bob's public key (PUK)
- Protocol Parameters:
    - M_1: Message that Alice sends to Bob in the exchange
    - M_2: Message that Bob sends back to Alice

### Protocol

1. Alice:
    - picks random seed _s_
    - derives: id <- HMAC(_s_, "id")
    - derives: ek <- HMAC(_s_, "encryption key")
    - gets invite token _tok_ from the server, picked from her basket of available P2P invite tokens (see below)
2. Alice:
    - Sends (id, _tok_, Enc(ek, M_1), Enc(PUK, s)) to server
    - Sends _s_ and hostname to Bob over WhatsApp/Signal/iMessage E2EE channel, along with AppStore intent, etc
4. Bob:
    - Derives id, ek from _s_
    - Fetches _tok_, Enc(ek, M_1) from server
    - Decrypts M_1; M_1 is displayed to user
    - Signs up for FOKS with _tok_
    - Sends (id, Enc(ek, {M_2, U_B, P_B})) to server
    - Grants Alice viewership to his user
5. Alice:
    - Loads inbox:
        - Sees both messsages:
            - (id, _tok_, Enc(ek, M_1), Enc(PUK, s))
            - (id, Enc(ek, {M_2, U_B, P_B}))
        - Uses the first and PUK to decrypt s
        - Rederives ek
        - Decrypts M_2, U_B, P_B
        - If answer M_2 is acceptable, adds U_B to T
    - Note, that because M_1 and M_2 are personalized, other team admins don't see this invite sequence

## Invite Flow, If Alice Can See Bob (and vice versa)

- Regular DM chat back and forth
- Alice sees option: "Admit Bob into team", which then opens a flow to pick Bob's membership on team
    - Also works vice-versa

## Invite Flow, if Alice and Bob cannot see each other

- Protocol flow is as above, using 3rd party app to exchange seed _s_
- _tok_ is not needed, since Bob already has an account
- otherwise, flow is the same

## P2P Invite System

- Configurable on a "big top server"
- Users get a starting budget of total invites, and a per-diem allocation
- Admin can give certain users more or less, based on an exceptions table
- Users can only sign up with an acceptable unused invite token in this mode
