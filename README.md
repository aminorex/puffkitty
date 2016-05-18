# nonce scripts

Contents::

cron-scripts:

    block_nasty.py -- 
        Checks in /var/log/auth.log (and its old, possibly compressed
	rolled versions) for [preauth] disconnects &c,
	which are new (since last execution), and blocks IPs which
	have demonstrated at least N (default 8) authentication failures.
	
	The timestamp is saved in $HOME/.block_nasty.stamp afterwards,
	and read on the next start-up, to determine which timestamp regions
	merit another inspection.  [preauth] failures before that time are 
	not counted (or even read, mostly).

