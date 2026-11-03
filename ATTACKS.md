# Attacks

<!--
Complete one block per attack. Replace every ___ and every <...> with your own
answer. 

Each attack must target a DIFFERENT security requirement (SR1-SR5), and must
run in both modes:
  python3 <your_attack>.py              (normal mode: the attack should FAIL)
  python3 <your_attack>.py --insecure   (insecure mode: the attack should SUCCEED)

Running against --insecure is how you show the defence is doing the work: the
same attack that fails normally succeeds once the defence is weakened. Your
script should print clearly whether the attack succeeded or failed.
-->

---

## Attack 1: <name>

| | |
|---|---|
| Security requirement targeted | <which SR (SR1-SR5), and what it requires> |
| What the attacker achieves | ___ |
| What the attacker can do (under the threat model) | ___ |

**Running the attack**

```
<command to run the attack in normal mode>
<command to run the attack in insecure mode>
```

Any set-up (which programs to start first, and in what order), or "None": ___

**Expected output**
- Normal mode (attack fails): ___
- Insecure mode (attack succeeds): ___

**Defence**

| | |
|---|---|
| What stops the attack in normal mode? | ___ |
| Where (file, function, lines) | ___ |
| What `--insecure` changes to let the attack through | ___ |

---

## Attack 2: <name>

| | |
|---|---|
| Security requirement targeted | <which SR (SR1-SR5), and what it requires> |
| What the attacker achieves | ___ |
| What the attacker can do (under the threat model) | ___ |

**Running the attack**

```
<command to run the attack in normal mode>
<command to run the attack in insecure mode>
```

Any set-up (which programs to start first, and in what order), or "None": ___

**Expected output**
- Normal mode (attack fails): ___
- Insecure mode (attack succeeds): ___

**Defence**

| | |
|---|---|
| What stops the attack in normal mode? | ___ |
| Where (file, function, lines) | ___ |
| What `--insecure` changes to let the attack through | ___ |
