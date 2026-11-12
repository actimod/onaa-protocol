# ONAA Design Principles

These principles guide the specifications and reference code in this repository. Code comments refer to them by number.

0. **Working name.** ONAA = Open Network for AI Agents. It is a working project name; no trademark registration or domain ownership is implied. Identifiers use URNs (for example `urn:onaa:a2a-ext:commerce:v0`) so that no domain is implied.
1. **Registry for discovery, agents for trade.** The registry handles discovery, search, registration and trust metadata. Buyer, seller and provider transactions run **directly** between agents over interoperable endpoints. The registry never relays trade messages.
2. **One open registry for every role.** Buyer, seller, payment, escrow, insurance, shipping, inspection, dispute, identity and hosting services can all join the same registry.
3. **External providers first.** Independent companies host seller nodes and supply regulated services (payment, escrow, insurance, logistics).
4. **Free basic listing.** Basic listing is free. Verification and certification are separate, optional services.
5. **Level playing field.** Any future first-party payment, escrow or insurance service must use the same public specifications as external providers.
6. **Built in the open.** Specifications evolve with the developers and providers who use them.
7. **Global by default.** English-first materials, with regional service and legal restrictions stated explicitly.
8. **Trust levels are distinct.** Discovered (unclaimed), registered, endpoint verified, identity verified and certified are reported separately, and none implies another.
