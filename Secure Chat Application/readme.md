
# Remote System Login

To log into the remote system, use the following command:

```bash
ssh ubuntu@10.200.13.114
```

---

# Task 1: Certificate Overview

The **Certificate** folder contains all of the Certificate Signing Requests (CSRs) and certificates for CA, Alice, and Bob.

---

# Task 2: Secure Chat Setup

### Steps:
1. Run `Makefile_bob_task2` in Bob's container (located in the `/root` directory):
    ```bash
    make -f Makefile_bob_task2
    ```
2. Run `Makefile_alice_task2` in Alice's container (located in the `/root` directory):
    ```bash
    make -f Makefile_alice_task2
    ```
3. On Bob's side, select the communication type:
    - For **encrypted communication**:
      ```bash
      chat_STARTTLS_ACK
      ```
    - For **unencrypted communication**:
      ```bash
      chat_STARTTLS_NOT_SUPPORT
      ```
4. Send and receive messages between Alice and Bob.
5. To end communication, send `chat_close` from either side.

---

# Task 3: MITM Attack Simulation

### Steps:
1. Poison Alice and Bob's containers on the host by running:
    ```bash
    ./poison-dns-alice1-bob1.sh
    ```
2. Run `Makefile_bob_task3` in Bob's container:
    ```bash
    make -f Makefile_bob_task3
    ```
3. Run `Makefile_trudy_task3` in Trudy's container:
    ```bash
    make -f Makefile_trudy_task3
    ```
4. Run `Makefile_alice_task3` in Alice's container:
    ```bash
    make -f Makefile_alice_task3
    ```
5. Send and receive messages over the **unencrypted** channel.
6. Eavesdrop on Alice and Bob's communication using Trudy's container.
7. Send `chat_close` from either side to stop communication.
8. To unpoison, run:
    ```bash
    ./unpoison-dns-alice1-bob1.sh
    ```

---

# Task 4: Encrypted MITM Attack

### Steps:
1. Poison Alice and Bob's containers:
    ```bash
    ./poison-dns-alice1-bob1.sh
    ```
2. Run `Makefile_bob_task4` in Bob's container:
    ```bash
    make -f Makefile_bob_task4
    ```
3. Run `Makefile_trudy_task4` in Trudy's container:
    ```bash
    make -f Makefile_trudy_task4
    ```
4. Run `Makefile_alice_task4` in Alice's container:
    ```bash
    make -f Makefile_alice_task4
    ```
5. On Bob's side, choose the communication mode:
    - For **encrypted communication**:
      ```bash
      chat_STARTTLS_ACK
      ```
    - For **unencrypted communication**:
      ```bash
      chat_STARTTLS_NOT_SUPPORT
      ```
6. Send and receive messages (encrypted or unencrypted).
7. Perform a **Man-in-the-Middle (MITM)** attack on Trudy's container to tamper/eavesdrop.
8. End communication using `chat_close`.
9. Unpoison the containers by running:
    ```bash
    ./unpoison-dns-alice1-bob1.sh
    ```

---

# Manual Execution without Makefiles

### Task 2

#### Alice's side:
1. Log in:
    ```bash
    lxc exec alice1 bash
    ```
2. Navigate to the programs directory:
    ```bash
    cd programs
    ```
3. Compile:
    ```bash
    g++ sec_server_client.cpp -lssl -lcrypto -o sc
    ```
4. Run the client:
    ```bash
    ./sc -c bob1
    ```
5. Send and receive messages.
6. Close the connection by sending `chat_close`.

#### Bob's side:
1. Log in:
    ```bash
    lxc exec bob1 bash
    ```
2. Navigate to the programs directory:
    ```bash
    cd programs
    ```
3. Compile:
    ```bash
    g++ sec_server_client.cpp -lssl -lcrypto -o sc
    ```
4. Run the server:
    ```bash
    ./sc -s
    ```
5. Choose communication:
    - For TLS:
      ```bash
      chat_STARTTLS_ACK
      ```
    - Without TLS:
      ```bash
      chat_STARTTLS_NOT_SUPPORTED
      ```
6. Send and receive messages.
7. Close the connection with `chat_close`.

---

### Task 3: MITM Attack

#### Alice's side:
1. Log in:
    ```bash
    lxc exec alice1 bash
    ```
2. Navigate to the programs directory:
    ```bash
    cd programs
    ```
3. Compile:
    ```bash
    g++ sec_server_client.cpp -lssl -lcrypto -o sc
    ```
4. Run the client:
    ```bash
    ./sc -c bob1
    ```
5. Send and receive messages.
6. Close the connection using `chat_close`.

#### Bob's side:
1. Log in:
    ```bash
    lxc exec bob1 bash
    ```
2. Navigate to the programs directory:
    ```bash
    cd programs
    ```
3. Compile:
    ```bash
    g++ sec_server_client.cpp -lssl -lcrypto -o sc
    ```
4. Run the server:
    ```bash
    ./sc -s
    ```
5. Choose communication:
    - For TLS:
      ```bash
      chat_STARTTLS_ACK
      ```
    - Without TLS:
      ```bash
      chat_STARTTLS_NOT_SUPPORTED
      ```
6. Send and receive messages.
7. Close the connection with `chat_close`.

#### Trudy's side:
1. Log in:
    ```bash
    lxc exec trud1 bash
    ```
2. Compile the downgrade script:
    ```bash
    g++ downgrade.cpp -lssl -lcrypto -o dg
    ```
3. Run the script to eavesdrop:
    ```bash
    ./dg
    ```

To unpoison the containers, run:
```bash
./unpoison-dns-alice1-bob1.sh
```

---

### Task 4: Encrypted MITM Attack

#### Alice's side:
1. Log in:
    ```bash
    lxc exec alice1 bash
    ```
2. Navigate to the programs directory:
    ```bash
    cd programs
    ```
3. Compile:
    ```bash
    g++ sec_server_client.cpp -lssl -lcrypto -o sc
    ```
4. Run the client:
    ```bash
    ./sc -c bob1
    ```
5. Send and receive messages.
6. Close the connection using `chat_close`.

#### Bob's side:
1. Log in:
    ```bash
    lxc exec bob1 bash
    ```
2. Navigate to the programs directory:
    ```bash
    cd programs
    ```
3. Compile:
    ```bash
    g++ sec_server_client.cpp -lssl -lcrypto -o sc
    ```
4. Run the server:
    ```bash
    ./sc -s
    ```
5. Choose communication:
    - For TLS:
      ```bash
      chat_STARTTLS_ACK
      ```
    - Without TLS:
      ```bash
      chat_STARTTLS_NOT_SUPPORTED
      ```
6. Send and receive messages.
7. Close the connection with `chat_close`.

#### Trudy's side:
1. Log in:
    ```bash
    lxc exec trud1 bash
    ```
2. Compile the fake certificates script:
    ```bash
    g++ /root/fake_certs/fake_certs/downgrade_task4.cpp -lssl -lcrypto -o dg
    ```
3. Run the script for MITM attacks:
    ```bash
    ./dg
    ```

To unpoison, run:
```bash
./unpoison-dns-alice1-bob1.sh
```
