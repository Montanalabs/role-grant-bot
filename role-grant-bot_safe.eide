#! Role-grant bot — untrusted a command can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires assignRole — the role-grant bot sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant assignRole

type Role = Viewer | Editor | Owner
type Decision = GrantRole(Role) | Deny

let raw = fetch<web>  # UNTRUSTED a command — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
using assignRole { privileged { assignRole(d) } }  # act on the trusted decision only
