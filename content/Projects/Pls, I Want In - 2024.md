---
description: Infrastructure, architecture, and challenges from the Pls, I Want In attack-defence CTF.
tags:
  - project
date: 2024-05-11
---
> [!Abstract] Introduction
> **Pls, I Want In** was an attack-defence CTF developed over the course of 8 months by me and a group of friends. This post will go through the architectural decisions, infrastructure, and challenges we faced during development, as well as how the game ran on competition day.

---
# Introduction
Hello! My name is James Lowther, and I'm a cloud infrastructure developer with (at the time of this post) 3 years of professional experience managing cloud resources in AWS. 

About 8 months ago, me and a group of friends decided to take a stab at developing our own attack-defence CTF. For me, this was something far more complicated than anything I had done before. Many of us on the team have previous experience hosting jeopardy-style CTFs before, but the dynamic nature of A/D CTFs was daunting. Nevertheless, we started development in September 2023, and held the first iteration of **Pls, I Want In** on May 11th, 2024.

This post will outline the successes and challenges we faced developing **Pls, I Want In**, while diving deep into the technical nitty-gritty that we had to learn in order to run the competition.

# What is an attack-defence CTF

> [!Tip]
> If you don't like reading, this [video by LiveOverflow](https://www.youtube.com/watch?v=RkaLyji9pNs) provides a more illustrative example of how the game works.

An attack-defence (A/D) CTF is a unique form of cybersecurity competition where teams are given identical vulnerable servers (vulnboxes) which contain application code with intentionally placed vulnerabilities. These services are often HTTP-based, such as web services, or TCP-based, which have a CLI interface that can be accessed with tools like netcat. Each service contains common security vulnerabilities such as SQL-injections, SSRFs, template-injections, buffer-overflows, and many more.

What's important to understand is that each team's vulnbox is identical. This means that any vulnerabilities a team finds on their own server, they also know exists on the services for every other team. The goal of the game is to patch as many exploits as you can on your own services, while simultaneously exploiting other team's services.
## Ticks
The game runs on intervals known as "ticks", which are 2 minutes long. Every tick, a number of tasks are run by the game server, such as updating the score, checking SLA, and inserting flags into services.
## Points
Points are calculated in one of three ways: **attack**, **defence**, and **SLA**. 
### Attack points
Attack points are accumulated by stealing "flags" from other teams. Flags are just random strings of text that are valid for gaining points. Once per game tick, new, unique, flags are inserted into each team's services by the game server. By exploiting vulnerabilities, teams are able to steal these flags and submit them for points.
### Defence points
Defence points are lost when another team steals your flags. This means you have an unpatched exploit in your services that another team is taking advantage of.
### SLA points
SLA points are gained when your services are up and functional. Once per tick, each of your services are checked to make sure they are working as expected strictly from a functional perspective. If your service is behaving incorrectly, or is completely down, you will start to lose SLA points.
## Skills
We like A/D CTFs because they force you to learn a wider variety of skills compare to a jeopardy CTF. It provides an opportunity to improve your skills in areas such as red/blue team cyber security, software development, devops, and many more. The competition is very dynamic, meaning you have to be very reactive to the attacks of other players.
# Development goals
When we first started talking about the prospect of actually building an attack-defence CTF, the following goals were identified:

1. Create the infrastructure and services for a small-scale A/D CTF, suitable for beginners.
2. Create a vulnbox that will have 1-3 services, and can be played within 3-4 hours.
3. Host the competition in AWS using cloud-native practices, implementing scaling where we can.
4. Creating good documentation and architecture diagrams.
5. Everything as code, and as much automation as we can.
6. Pipelined as much as we can.
7. Monitoring, such as metric/log collection, as much as we can.
8. Do it as cost-effective as possible, within reason.

I pushed for developing the competition using AWS, because it is the cloud provider that I have the most professional experience in. I wanted to take this opportunity to improve my knowledge of cloud best-practices, such as infrastructure scaling and automation. I wanted the infrastructure to be suitable to competitions of many sizes, allowing it to easily be scaled out to support larger events.

As you will see in the remainder of this post, some of these goals we were very successful in completing, and others... not so much.
# Architecture
 Our architecture diagrams evolved over time as we learned better ways to solve our problems. Here is the final architecture diagram for **Pls, I Want In** 2024:
 ![[plsiwantin-architecture-v3.png]]

## VPCs
Our infrastructure had of two VPCs, the "Main" and "Team" VPC. These two VPCs were configured with a VPC peering connection, allowing resources within them to communicate. By creating two VPCs, we were able to easily differentiate between what IPs were organizer-controlled, and which were team-controlled just by using a `/16` CIDR.

The team VPC only contained the subnets and EC2s that teams would have control over. This VPC is where the team-controlled vulnboxes lived.

The main VPC had everything else. This included the OpenVPN servers, routers, game server instances, monitoring, and checkers.

## Subnets
The way our subnets were configured was primarily driven by the routing requirements that we had. For example, EC2s in the checker subnet needed a specific route in order to reach the vulnboxes. By architecting our subnets this way, it made it easier for us to write the route tables to control traffic flow.

You may notice most of the subnets are deployed in the same AZ. This was intentionally decided as a cost-saving measure, as AWS charges you for cross-AZ traffic. If we wanted to make this more fault-tolerant, we could deploy servers across AZs, but for such a short competition AZ failure was not a major concern.
## Routing
For an A/D CTF, it is important that teams are not able to infer where traffic is coming from. This means that when a vulnbox receives a packet, it should be impossible to tell if that packet originated from a checker, or from another team's vulnbox. This is to prevent teams from blocking traffic from other teams, thus protecting their flags, while only allowing the checkers through.

I'll speak more about how we implemented this in the [Router](#router) section of this post, but most of this was handed using custom route tables on the subnets, a gateway load balancer, and iptables.
## Internet
Team connectivity from the internet was enabled through load-balanced OpenVPN servers in a public subnet. We also had a NAT gateway to easily handle egress internet access from EC2s in our private subnets.

We have two public internet subnets because it is the minimum number required to deploy an application load balancer.

## V1 Diagram
The complexity increased dramatically as we added more and more into the scope of what we wanted to do. For example, here was the V1 diagram:
![[Pasted image 20240513150030.png]]
# Game server
 The game server we went with was created and documented by the [FAUST CTF](https://faustctf.net/) team. It is by far the best A/D CTF platform we have seen, and was rock-solid stable for our competition. Check out the [documentation](https://ctf-gameserver.org/) and [source code](https://github.com/fausecteam/ctf-gameserver) for this project. They did a fantastic job, and a lot of the success of **Pls, I Want In** can be attributed to them.
## Web interface
The front-end for the game server is a standard Django application. We hosted it using uWSGI in master mode, with 4 processes with 2 threads each.

```ini
[uwsgi]
uid = www-data
gid = www-data

chdir = /opt/ctf-web
plugins = python3

master = true
die-on-term = true

processes = 4
threads = 2

module = django.core.wsgi:get_wsgi_application()
env = DJANGO_SETTINGS_MODULE=prod_settings

socket = /run/ctf-web/socket
chmod-socket = 660
vacuum = True

buffer-size = 16384
```

> [!Tip]
> It was important we increased the `buffer-size` up to `16384`, as we would get 500 errors without it.

This uWSGI process created a unix socket that was reverse-proxied with nginx. To simplify TLS, we provisioned a wildcard certificate for `*.plsiwant.in` using AWS ACM which was then attached to an application load balancer. The target group for that ALB then forwarded traffic to the nginx server over HTTP.
### Database
The database we used was a simple PostgreSQL instance running under Docker. To configure the database users and permissions we heavily referenced the database roles from the FAUST [ctf-gameserver-ansible](https://github.com/fausecteam/ctf-gameserver-ansible) repository.
### Caching
The Django application was configured to use memcached for it's caching backend. The backend we initially chose was was `PyLibMCCache`, but we started seeing a large number of 500 errors even with a tiny amount of traffic. We ran a load test and compared it with the `PyMemcacheCache` backend.

Run #1 was `PyLibMCCache` and Run #2 was `PyMemcacheCache`:

![[Pasted image 20240513154423.png]]

> [!Error]
> `PyLibMCCache` had a nearly 37% failure rate! Switching to `PyMemcacheCache` solved nearly all of our performance issues with the web server.

The lesson here was to load test **everything**, as issues will pop up even on the smallest parts of your infra.
## Controller
The controller service is in charge of changing the game tick, and coordinating the flags for each service. This ran as a single service on our game server EC2 instance and required access to the database.
## Checker
The checkers are responsible for checking team service functionality, placing new flags, and verifying previously placed flags are still available. We ran the checker on multiple EC2s to ensure we could quickly recover from instance failure. We used the `CTF_CHECKERCOUNT` environment variable to ensure team checks were equally distributed across each server. With this implementation we could easily scale the competition size by increasing the number of checker servers.

All of our checkers were written in Python and had their own virtual environment with any custom modules that were requested. The checkers require access to the database to function.
## Submission
The submission endpoint was found at `submit.plsiwant.in` on port `1337` and is a simple TCP endpoint that has a protocol for accepting flags from teams, allowing them to gain points. We ran three submission services on the game server EC2, and used nginx to transparently load balance packets across them.

> [!Info]
> The submission server used the third octet in the source IP to determine who to give points to. For example, a team with a net number of 3 would submit flags from an IP `X.X.3.X`. This could be from their vulnbox, or locally from their OpenVPN connection.

With the submission servers running on ports `10000`, `10001`, and `10002`, the nginx configuration looked like this:
```nginx
stream {
	upstream stream_backend {
		server 127.0.0.1:10000;
		server 127.0.0.1:10001;
		server 127.0.0.1:10002;
	}

	server {
		listen 1337;
		proxy_bind $remote_addr transparent;
		proxy_pass stream_backend;
	}
}
```

We then added the following IP rules to transparently proxy the packets to nginx:
```bash
ip route add local 0.0.0.0/0 dev lo table 100

ip rule add from 127.0.0.1/32 ipproto 6 sport 10000 iif lo lookup 100
ip rule add from 127.0.0.1/32 ipproto 6 sport 10001 iif lo lookup 100
ip rule add from 127.0.0.1/32 ipproto 6 sport 10002 iif lo lookup 100
```

The submission service is one we could run across multiple servers, but it was so performant we didn't feel the need to.
# OpenVPN
It was important that an OpenVPN server could fail completely and the game would still run. This led us to figure out how to load balance teams across OpenVPN instances, allowing us to scale out dynamically if our CPU load got too high.

> [!Info] VPN Services
> Each team had their own OpenVPN service running on each VPN server, with their own interface. For example, team 7 had an OpenVPN service running on each VPN server that used `tun7` as its interface.

One obvious solution to the load problem this is to shard teams across multiple instances, but this doesn't solve the problem of high availability. If 1/4 of all teams are sharded on a single VPN instance, and that instance fails, then those users will experience downtime. To solve this, we used DNS-based load balancing and multiple OpenVPN servers. By having a DNS A-record with multiple addresses, OpenVPN will randomly choose one of them each time the domain is resolved.

OpenVPN has a good, but short, [article on load balancing](https://openvpn.net/community-resources/implementing-a-load-balancing-failover-configuration/) that recommends putting identical configuration files on each server, but changing the virtual address pool. This is something we didn't want to do, as it would increase the chance of CIDR overlap issues on competitors local networks. We advertised that the route we would be pushing over to people's locals was `10.66.X.0/24`, with `X` being their team net number, and I wanted that to be the same regardless of which of our VPN servers they were connected to. We didn't want VPN A to push `10.66.X.0/24` and VPN B to push `10.67.X.0/24`.

This introduces a new problem. If each virtual IP pool is the same, how do we ensure that a connection sent from VPN server A is route back to VPN server A? The obvious answer is to add some sort of SNAT on each server, but due to the unique nature of A/D CTFs, we had to keep the third octet static for each team to support proper flag submission.

> [!Warning] Remember
> The third octet of a packet's source is used by the submission server to determine who to give flags to. A request sent from `10.66.10.6/32` with a valid flag should give points to team 10. If we NAT the packets, all of the packet sources will be the same.

To solve this, we used a iptables rule type known as NETMAP. NETMAP builds a one-to-one translation for an entire subnet, allowing us to change the first 16 bits in the source address while leaving the bottom 16 untouched. It can sort of be thought of as a SNAT, but only for the first 16 bits.

- VPN A: `10.66.X.0/24` -> `10.80.X.0/24`
- VPN B: `10.66.X.0/24` -> `10.81.X.0/24`
- VPN C: `10.66.X.0/24` -> `10.82.X.0/24`

For example, for a client from team 7 to VPN B their packets from `tun7` would have a source that might look like `10.66.7.20`. When that packet leaves VPN B, the packet would be translated to `10.81.7.20`.

For anything that needs to communicate to the VPN servers, we can then add routes in the route table for `10.80.0.0/16`, `10.81.0.0/16`, and `10.82.0.0/16` to the ENIs for VPN A, VPN B, and VPN C, respectively.

![[VPN Scaling-Scalable.png]]

To ensure that we have identical OpenVPN configs on each server we used a AWS Elastic File System (EFS) network file share. This made is trivial to share the OpenVPN server config files across EC2s.

> [!Success]
> With this implementation, we could load balance OpenVPN connections across multiple servers completely transparently to the end user. We could increase the number of servers to handle increased load without having to manually shard connections.
> 
> One improvement would be to add a network load balancer in front of our OpenVPN servers. This would reduce the number of public IPs required when scaling.
# Router

# Vulnbox

# Pipelining

# Monitoring

# Game day