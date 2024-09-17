
# maTLS: Securing Communications with Auditable Middleboxes

## Introduction
This project enhances the security of TLS in environments with middleboxes (MBs) through **maTLS** (middlebox-aware TLS). Unlike SplitTLS, which introduces vulnerabilities, maTLS ensures transparency, accountability, and stronger security in multi-segment connections.

## Problems with SplitTLS
1. **Authentication**: The client cannot authenticate the server when MBs replace certificates.
2. **Confidentiality**: Clients negotiate keys with MBs, weakening security.
3. **Integrity**: MBs can modify data, but clients cannot detect unauthorized changes.

## Solution: Auditable MBs
- **MBcert**: Provides details of MB roles and permissions.
- **Properties**:
  - Clients can detect unauthorized modifications.
  - MB actions are publicly auditable, eliminating SplitTLS risks.

## maTLS Overview
maTLS enhances TLS 1.2 by introducing:
1. **Authentication**: Both server and MBs are authenticated.
2. **Confidentiality**: Each segment has strong cipher suites with unique session keys.
3. **Integrity**: Clients verify data sources and track modifications.

---

## Workflow Summary
- **Key Exchange**: Clients, servers, and MBs exchange secure keys through segmented TLS connections.
- **Audit Mechanism**: Clients verify MB actions and security parameters to ensure data integrity.

---

## Secure Chat Implementation Using Containers

This implementation uses containers in the VM for secure chat assignment.

### Container Setup:
- **Alice1**: Client
- **Trudy1**: MiddleBox
- **Bob1**: Server

### File Transfer Process:
- Files are sent to the VM using `scp` command.
- Respective certificates and Python scripts are sent to each container using the `lxc file push` command.

### Container File Distribution:
- **Alice1**: `client.py`, `root.crt`, `root.key`
- **Trudy1**: `mb.py`, `mb_cert.crt`, `mb_key.pem`, `root.crt`, `root.key`
- **Bob1**: `server.py`, `server_cert.crt`, `server_key.pem`, `root.crt`, `root.key`

### Experimental Run:
1. **Bob1**: Run the server
   ```bash
   $ python3 server.py 
   ```
2. **Trudy1**: Run the middlebox (acting as man-in-the-middle)
   ```bash
   $ python3 mb.py alice1 bob1
   ```
3. **Alice1**: Run the client to connect to Bob1
   ```bash
   $ python3 client.py bob1
   ```
