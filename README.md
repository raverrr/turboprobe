# TurboProbe: Fast Webserver Detection on Port 443

Throwing caution to the wind and attempting to loosely deduce if a webserver is running on port 443 as fast as I can, at the expense of accuracy.

## Why?

What a massive waste of time... Yes and no. I have a list of 15 million subdomains I want to probe for webservers. I'd love to be super accurate, but I have the attention span of a toddler, and running a scan for days—or even weeks—is just... eugh. I'd cancel it. So, I wondered: at what point in a TCP connection can we deduce a webserver's presence? Turns out, for real accuracy, you need to wait for the HTTP response. But what if I don’t care that much about accuracy, as long as it’s not totally useless?

I assumed that if a subdomain responds on port 443, there’s a decent chance a webserver’s running there. The earliest point to check is the SYN-ACK part of the handshake. So, that’s what I went with.

## How It Works

TurboProbe deduces a webserver on port 443 based solely on receiving a SYN-ACK. It’s a silly, probably unsafe approach since any service could be on that port. The goal here is speed, not accuracy. By dropping connection attempts that don’t return a SYN-ACK fast enough—and quickly moving on even when one *is* received—I skip all the overhead of completing an HTTP request to confirm a webserver.

One bottleneck I couldn’t dodge: timeouts. The initial response takes however long it takes, and there’s not much I could do about it.

## Performance

Here’s how TurboProbe stacked up (tested on the second-lowest tier Ubuntu VPS on Digital Ocean, concurrency at 200, timeout at 500 milliseconds):

- Over 3,394 subdomains, TurboProbe reported 874 responding on port 443 in **4 seconds** (hinting at webservers).
- A popular, slower, but far more accurate tool found 1,013 webservers in **8 minutes and 41 seconds**.

That’s about 86% of the accurate tool’s findings in roughly 0.8% of the time. Winning! The main accuracy hit came from the 500ms timeout per operation—speed over precision, as always.

## Observations

Some notes from testing:

- I left other popular tools on their default settings to keep their accuracy intact. For instance, they often use 10- or 20-second timeouts to catch slower servers, while TurboProbe’s at 500ms.
- Resource usage: TurboProbe’s RAM capped at 1.17 GB and stayed steady, with CPU bouncing between 70% and 100%. Conventional tools matched the CPU load but often used over twice the RAM.
- The 15 million subdomain scan? The scan completed in 3hours and 49 minutes and found 872019 webservers.  

## Disclaimer

Why you *shouldn’t* use TurboProbe:

- It needs **root privileges** for low-level packet stuff. Running some stranger’s tool as root? Sketchy move.
- It’s **inaccurate**. Detecting ~86% of what a proper tool finds works for me, but if you want precision and have more patience, pick a better tool—there are plenty.
- It might get you **owned** in some clever way I haven’t figured out yet.

## So Why Share?

I was bored, and messing with this kept me entertained for a few hours. Maybe someone else will find it mildly interesting too.
