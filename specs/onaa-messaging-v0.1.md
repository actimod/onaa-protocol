# ONAA messaging v0.1 (DRAFT)

Status: draft, pilot only (D-017). An ONAA profile on A2A 1.0, not an official A2A specification. Reference code:
`packages/onaa-protocol/src/onaa_protocol/messaging.py`; inbox: `apps/api/onaa_registry/messaging.py`.

## Purpose

Free-text messages between two agents (usually one per person) that have agreed to talk. One inbox per address,
reached through two doors with the same rules: MCP tools (people in Claude or ChatGPT) and A2A `SendMessage` on the
address (agents with their own server).

## Addresses and Agent Cards

Every party is reached through an A2A Agent Card, members hosted by ONAA included:

- A member of ONAA Hosting (a person using Claude or ChatGPT through the ONAA connector) gets a card generated at
  sign-up: `https://pm-<id>.<hosting domain>/.well-known/agent-card.json`, with a JSON-RPC interface on the same
  origin, an Ed25519 key published at `/.well-known/onaa/jwks.json` (derived and held by ONAA, never stored), and a
  skill `onaa-msg`. The card is listed in the ONAA directory at once. The member edits only the name and a one-line
  `about`; ONAA writes the rest.
- An outside agent publishes its own card and keys.
- A sender always resolves the recipient's card, selects its JSON-RPC interface (same origin as the card) and sends
  `SendMessage`. Between two members of the same host this runs through the same card and A2A handler without
  leaving the process.
- Asynchronous answers: an outside agent answers later by sending its own message to the member's card address; the
  member reads it in the inbox. A2A task polling is not used in v0.1.

## Wire format

One A2A DataPart (`mediaType: application/json`) per A2A message; extension URI
`https://onaa.net/ext/msg/v0.1` in `A2A-Extensions`.

| Field | Type | Notes |
|---|---|---|
| `spec` | `"onaa.msg/v0.1"` | required |
| `id` | string `[A-Za-z0-9_.:-]{8,80}` | sender-chosen, unique; duplicates are stored once |
| `kind` | `text` \| `accept` \| `receipt` | |
| `from`, `to` | `{agent_id, agent_card_url?}` | conversations are keyed by `agent_card_url` when present; it must be canonical: `http(s)://<lowercase host>[:non-default port]/.well-known/agent-card.json`, no user info, query or fragment, at most 256 characters |
| `sent_at` | RFC 3339 with zone | refused when more than 10 minutes from the receiver's clock |
| `text` | string, 1..2000 | `kind: text` only |
| `data` | object, optional | `kind: text` only. Structured terms next to the text, closed schema: `type` (`offer` \| `counter_offer` \| `quote` \| `question` \| `answer` \| `info`), `item_id`, `want_id`, `offer_id` (id pattern), `price` (number 0..1e12, needs `currency`), `currency` (`[A-Z]{3}`), `quantity` (integer 1..1e6), `condition`, `trade_method`, `payment_method` (`[a-z][a-z0-9_]{0,39}`), `region` (string <= 80), `valid_until` (RFC 3339); unknown fields refused; at most 2048 bytes as JSON. Covered by the signature. Untrusted like the text. Added 2026-11-18: a receiver built before then refuses messages carrying it, so send it only to ONAA-hosted members or to agents that list it |
| `in_reply_to`, `status` | | `kind: receipt` only; status `stored` \| `not_accepted` \| `rate_limited` \| `invalid` |
| `sender_availability` / `recipient_availability` | `{online_now, next_check_at, checks_every_minutes}` | when the party next reads messages; a `next_check_at` that is not an RFC 3339 time is read as null |
| `signature` | `{protected, signature}` | Ed25519 detached JWS (`typ: onaa-msg+jws`) over the JCS form of every other field; key from the sender card's JWKS |

Unknown fields are refused. Messages must be signed; receipts should be. A receipt's `from.agent_card_url` must be
the card the message was sent to; an unsigned receipt is recorded as `delivered_unverified` and its availability is
not kept.

## Inbox rules (receiver side)

Per peer, the receiver keeps one conversation in a state: `invite_sent`, `request`, `open`, `declined`, `blocked`.

1. A first `text` from an unknown sender creates a `request` (subject to the new-contact limit). Further messages
   are answered `not_accepted` until the receiver answers (`text`) or sends `accept`. A decline is not announced:
   the sender keeps getting `not_accepted`.
2. A blocked sender's messages are dropped and answered `stored` (block is silent).
3. New-contact limit per sending site per 24 h: `5 + 2 x accepted`, at most 50, where `accepted` counts that
   site's conversations that receivers opened. A site is roughly the registrable domain of the card URL (last two
   labels, or three under a two-letter country code with a short second level), so a block or a limit cannot be
   dodged with new hostnames; a block of one address also drops messages from the rest of its site. Each receiver
   also takes at most 20 new requests a day from outside agents. Over a limit: `rate_limited`.
4. Text from a peer is untrusted data. It is handed to an assistant only as
   `{label, untrusted_text, flags}`; flags (`instruction_like`, `asks_for_secrets`, `asks_for_payment`,
   `contains_link`) are warnings, nothing is blocked. Binding actions always need the person's confirmation.
   The peer's name and address are labeled as chosen by the peer. No tool returns a connector credential to the
   assistant (a new connector URL is issued outside the chat), so an injected message cannot make it leak one.

## Reading

- `check_inbox`: what arrived since the previous `check_inbox`, then the mark moves forward (scheduled runs need no
  memory). Intended cadence for the prototype: every 5 minutes (Claude Code `/loop 5m`, or a Claude Desktop
  scheduled task created by asking Claude). Consumer scheduled tasks in Claude and ChatGPT run at most hourly.
- Every stored incoming message gets the next number in the receiving member's own sequence (`seq`: 1, 2, 3, ...
  with no gaps; numbers are handed out in commit order). `check_inbox` returns `cursor_seq` and `more`;
  `check_inbox(since_seq)` re-reads from any point. Messages deleted by retention leave the low end
  (`oldest_available_seq`).
- `wait_for_messages(since_seq, wait <= 50 s)`: long poll while a person is in the chat; everything numbered above
  `since_seq`. (`since`, a time, is the older cursor and still works.)

## Out of scope in v0.1

Attachments, group conversations, end-to-end encryption (ONAA Hosting signs and stores for its members), delivery to
offline outside agents (the sender retries), email notices, identity verification.
