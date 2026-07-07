#! VULNERABLE role-grant-bot — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant assignRole

let raw = fetch<web>
using assignRole { privileged { assignRole(raw) } }  # tainted -> tool: REJECTED
