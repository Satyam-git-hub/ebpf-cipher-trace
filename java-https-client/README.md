# Java HTTPS Client for eBPF Testing

This simple Java program makes an HTTPS request to verify if the eBPF agent can trace Java applications.

## Prerequisites

You need `java` and `javac` installed.

```bash
sudo apt update
sudo apt install default-jdk
```

## Compilation

```bash
javac HttpsPing.java
```

## Running

```bash
java HttpsPing
```

## Expected output

You should see output similar to:
```
Connecting to https://www.google.com...
Response Code: 200
Cipher Suite: TLS_AES_128_GCM_SHA256
SSL Protocol: TLSv1.3
```

And your **eBPF Agent** should log an event for the `java` process.
