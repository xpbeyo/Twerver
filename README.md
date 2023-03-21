# Twerver

A C socket program that simulates a twitter experience.

To run:
```
make PORT=<port_num>
./twerver
```

Run `nc -C localhost <port_num>` as a client. It is expected to spawn multiple clients and have them follow each other. Followers can see messages posted by the followee. 

The server supports the following commands.
```
follow <username>
```
Follow a user with a username
```
unfollow <username>
```
Unfollow a user with a username
```
show
```
Show all messages posted by the users you followed.
```
send <msg>
```
Post a message.
```
quit
```
Disconnect from twerver.
