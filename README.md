# turboprobe
Throwing caution to the wind and attempting to loosely deduce if a webserver is running on port 443 as fast as I can at the expense of accuracy.

##Why? What a massive waste of time...
Yes and no....I have a list of 15 million subdomains I want to probe for webservers. I would like to be very accurate in this but I have the attention span of a toddler and running a scan for several days, even weeks is... eugh....I would just cancel it. So I wondered at what point in a TCP connection could we deduce the prescence of a webserver. Turns out that it looks like you 'need' to get all the way to the HTTP response if you want to do so with accuracy. But what if I don't really care about accuracy so long as it isn't a complete loss? Working on the assumption that if a subdomain responds on port 443, there is a reasonable probability that there is a webserver running on that port, the earliest possible point to look at is when the SYN-ACK portion of the handshake happens. So thats what I tried to do. 

This tool deduces the prescence of a webserver on port 443 from the reciept of a SYN-ACK only. This is really silly and probably unsafe because any service could be running on that port. The purpose here is speed at the expense of accuracy. By droping connections attempts that do not return a SYN-ACK quickly, and quickly dropping the connection and moving onto the next job if a SYN-ACK is recieved too, I avoid all of the overhead that comes with completing a httprequest following a handshake to confirm the prescence of a webserver. A bottle neck that I wasn't able to mitigate, is the need for a timeout on each request. Initial response just takes as long as it does and there isn't much I could do about that. 

Here is how the tool performed:
(tests performed on the second from lowest tier ubuntu VPS on Digital Ocean with concurrency set to 200 and timeout set to 500 milliseconds)
Over a list of 3394 subdomains, the tool reported that 874 of them responded on port 443 in 4 seconds (loosely implying the prescence of a webserver).
In comparison, a popular, much slower but much more accurate tool, reported 1013 webservers on port 443 in 8m41s.

This is roughly 86% of the findings but in about 0.8% of the time. WINNING.
One of the key losses in accuracy was down to my tests using 500 milliseconds as a timout for each operation. Again, sacrificing accuracy for speed.

Some comments/observations:
Wnen testing other popular tools against turboprobe, I left them on their default settings. This was to make sure I wouldn't, push a tool known for accuracy to be less accurate. For example, commonly, similar probing tool will work with timouts of 10 or even 20 seconds to make sure we don't miss out where servers might be slower to respond.

System resource usage was interesting. Ram usage in turbo probecapped out at 1.17 GB during my tests and didnt fluctuate much. CPU usage fluctuated between 70% and 100%.
The more conventional tools put a similar load on the processor but used more than twice the ram in some cases.

So, how did the 15 million subdomain scan go? 
It's still going. I started it an hour and a half ago. I estimate it will take between 5 and 8 hours. I'll update this page when it finishes.
So far it is still very recource efficient though. Sitting at 1.18 GB of ram and 35% to 55% CPU usage. (The low CPU usage appears to happen when the tool is not timing out on a lot of requests, this makes sense because I know for a fact that my 15 million list likely has less than 50% running webservers)

##Why you should probably not use this tool:
It requires root for the low level packet things. Running a tool from a stranger as root is generally not advised....
It is innacurate. 80 something percentaccuracy is fine for my needs. If you care about accuracy and you have more patience than me, just use a much better tool. there are many of them. 
Using it probably opens you up to being owned in some creative way that I'm not aware of. 

##So why share?
I'm bored and this test entertained me for a few hours so maybe reading it about it will be slighlty interesting to someone else. 

 
 
