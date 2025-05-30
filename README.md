**Public-key-signatures Report**  
**Author:** Omid Farahmand
---
# Secure Photo Synchronization and Device Management Implementation Report (2)
## Executive Summary Section:
This report will describe the design and the implementation of a secure photo-sharing system, which is expanded from assignment 1. The main focus of part 1 was to implement **multi-device synchronization**, **inviting** and **revoking devices** and also **securing friends’ photo sharing**. The way the system is designed is to keep the data protected and consistent even when the server or a device is malicious. Also, an HMAC chain has been used to keep the logs safe from being tampered with and to protect the authenticity of devices. Other tools like synchronization methods were put in place to make sure photo histories stay stable during the communications between users. There are also scenarios that should be considered: First is when the server is compromised, but the devices are honest; second is when both the server and the device are compromised. The goal is to keep the **data integrity** protected and detect any unauthorized action. HMAC validation, device revocation, and synchronization checks will help a lot during this process. The second part of the report will discuss some system security considerations. In this case, the encryption is used to efficiently keep the **chosen-plaintext attacks (CPA)** safe by integrating a randomized one-time pad using RSA encryption. This will make the message unique and unpredictable. However, in terms of **chosen-ciphertext attacks (CCA)**, there will be some weaknesses. This part will highlight the use of stronger protection against the CCA in future attacks. Overall, this report summarizes the implementation and the methods that have been implemented related to security consideration and evaluation of photo-sharing systems. It focuses on the system design to give stronger protection against different types of threats and attack models. Also considers areas for improvement in the security mechanism.

---

## Part 1: Implementation report
In this assignment, we extended and improved the secure photo-sharing system that was achieved in assignment 1. These are **multi-device synchronization, device invitation, revocations, accept and friend photo sharing**. We updated the system to invite and remove devices and be users to share photos with friends. In the previous assignment, cryptographic HMAC chains were used, which focused on the integrity and tampering resistance of a single device photo log. However, by improving our code in assignment 2, a single user can work with multiple devices, each having its own cryptographic key pair. In this case, device invitations are implemented using **InviteDeviceLogData** entries, which let multiple devices work together under the same username. This means that one authorized device can invite another device by including its public key in the log. Added from assignment 1:
```python
def _compute_log_hmac(
        self,
        version: int,
        opcode_val: int,
        photo_id: int,
        photo_hash: bytes,
        prev_hmac: bytes,
    ) -> bytes:
     
        data_for_mac = [version, opcode_val, photo_id, photo_hash, prev_hmac]
        encoded = codec.encode(data_for_mac)
        return self._symmetric_auth.gen_mac(encoded)
```
The devices that are invited will accept the invitation using the **AcceptInviteLogData** entry, which then becomes authorized. This will permit the user to upload photos or manage another device. After the new device is added, the log authorization system will make sure that permission of the past login is unchangeable and trackable. This is true because every **invitation, acceptance, and revocation** is recorded and secured by the **HMAC chain**. On the other hand, if the device is compromised, it will send an exception using the **RevokeDeviceLogData** entry, which will delete the compromised device’s public key from the system. This way, none of the other devices or their friends will trust anything in the future since they were compromised by the malicious servers. This will make sure to forward its integrity, meaning that if a device is revoked, it cannot modify its previous logs and future accesses. In this case, every invitation, acceptance, and revocation are recorded, so the malicious device cannot modify the log without being noticed. 

Moreover, a **friend photo-sharing** feature has also been added, which lets the user add different user friends and view their photos. For example, each friend will keep a local copy of their friend's photo and its log state, which is synchronized directly to the server. After this, the friend will verify the device integrity of the received log with its HMAC chain mechanism. This will make sure the user is legit and not **tampered** with the user’s log using its **self-verification**. It also does not let the malicious server sneak in fake photos, remove real ones, or even create conflict logs without being caught. Device revocation will deal with the situations when syncing with friends. If a device is revoked and attempts to upload pictures, the system responds with a **SynchronizationError** due to the inconsistency inside the log. This will avoid any mistake between a revoked device and authorized ones, which keeps the system secure. 

This assignment will make sure that, even in scenarios in which a device or the server may be compromised, friends and other devices can have an agreed and verifiable record of the user's photo history. This is a major improvement over Assignment 1 in moving from **single-device integrity** to **cross-device** and **multi-device consistency**, offering better guarantees against both malicious servers and compromised users. 

---

## Security Goals and Scenarios



The system protocol is put in place to prevent three main security scenarios: **compromise of a device when the server is honest**, **compromise of the server when devices are honest**, and **compromise of both server and device**. It will be covered in the thread model, implementation approach and code references below.

---

#### Device Compromise with an Honest Server:
In the case where a user device is compromised with an honest server, the system will make sure that their friend, when looking at their photos, can only see photos from devices that were **legit** at the time of upload. The **HMAC chain verification** can make this happen, as can device **revocation mechanisms**, which also stop unauthorized devices from modifying or deleting photo logs. This part will ensure that if a revoked device attempts to accept an invitation or authenticate itself, it will raise an exception:
```python
if accept_data.accepted_device_public_key in revoked_set:
    raise errors.SynchronizationError("Revoked device")
```
Also, as mentioned before, each photo is cryptographically verified before acceptance. This will make sure that the user’s friend only receives legitimate updates:
```python
elif log.opcode == OperationCode.PUT_PHOTO.value:
put_data = PutPhotoLogData.decode(log.data)
if put_data.device_public_key not in authorized:
raise errors.SynchronizationError("Photo uploaded by unauthorized device")
```
This method will ensure **integrity**, with only friends able to receive legitimate updates from a device that is trusted. 

---

#### Server Compromise with Honest Devices:
The next scenario is when the server is compromised with honest devices. In this case, it is still not permitted to **modify the logs, reorder actions or even tamper with data without getting detected**. Here, the HMAC chain will ensure the prefix attributes and check if users access logs history and only receive a verifiable portion of the original log, which prevents unauthorized alteration.
```python
this_hmac = self._compute_log_hmac(version, opcode.value, photo_id, photo_hash, prev_hmac)
entry = LogEntry(version, opcode, prev_hmac, this_hmac, data)
encoded_entry = entry.encode()
```

This chain mechanism will make sure that any modification in the previous log will break the chain. Since each **prev_hmac** should match the **this_hmac**. During the synchronization process, the client will compute the HMACs, and any inconsistency will reply back with a **SynchronizationError**. Therefore, this process will leave the server integrity of the logs intact, and the user can authenticate the data they receive. 

---

#### Compromise of Both Server and Device:

Lastly, the worst-case scenario is where both a device and the server are compromised. The protocol which is designed will detect and block any malicious activity. When a device is revoked, it will be added to its set to prevent accepting any invitation, authentication, or even uploading photos. For instance, if a revoked device tries to accept an invitation, it will raise a **SynchronizationError** to stop any thread regarding unauthorized access. Moreover, during the revocation, the system constantly verifies the **device authorization**. This will indicate only **legitimate devices** can communicate with the log. On the other hand, if the revoker and revoked devices try to upload updates after revocation, an **exception will be raised to stop the conflicting records**. Any mismatch in authorized devices during synchronization will give an error. 
```python
elif log.opcode == OperationCode.PUT_PHOTO.value:
put_data = PutPhotoLogData.decode(log.data)
if put_data.device_public_key not in authorized:
raise errors.SynchronizationError("Photo uploaded by unauthorized device")
```     

---

## Part 2: System Security Questions

The main job of encryption is to have a secure system against **chosen-plaintext attacks (CPA)**. This process can be achieved by introducing the new random value r for every message that is encrypted. During the encryption of the message m, the procedure is to make a random r of the same length and XOR m with r. This will ensure that even if the message is encrypted, several times, the outcome of the ciphertext will be different because of the new randomness presented by r. This randomness will make it impossible for an attacker to see the difference in the pattern or find out the original message. Moreover, the value of the r is encrypted using **RSA**, which is encrypted using a **large key-value size** and makes it **infeasible** for anyone who attempts to recover r from its encrypted t. This is especially true since the attacker can’t predict or control r, and the encrypted message and encrypted r will rely on it securely against chosen plain text attacks **(c = m XOR r)**. By gathering the **one-time-pad** with randomness of r with a strong RSA encryption, the process will make sure that if the attacker requests many encryption messages, there will not be any trace or pattern from the original message and the system to be broken. Therefore, the process effectively protects against **chosen-plaintext attacks**.

---

In terms of the **chosen-ciphertext attack (CCA)**, the system is not that reliable against attacks. This is true because it has no defence mechanism against the attacker from **tampering** with the ciphertext and the information that comes with the original message. In a chosen ciphertext attack, the attacker can make fake ciphertexts (c’, t’), asking the system to decrypt them. This process has two parts; the first is the c, which is XORed with the message combined with a random value **(c = m XOR r)** and t, where r is encrypted using the RSA **(t = r^e mod n)**. So, if the attacker wants to decrypt the message, it can create a new ciphertext **(c’, t’)** by choosing its random value r’. After that, it can compute the t’=r’^e mod n using its **public RSA key**. Another way is for the attacker to set the XOR of some of the target messages with r’ to any resulting value. The attacker can fully control c’ and r’ in this case since it knows r’. This means that the attacker can control and decrypt the message after the system decrypts its fake ciphertext, which indicates how unsafe the system will be. Having a secure system means that even if the attacker tricks the system into decrypting or modifying malicious ciphertext, they should not learn or gain **confidential information** about the system, which in this process, fails.







