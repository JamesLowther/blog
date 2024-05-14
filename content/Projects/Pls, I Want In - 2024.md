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

I'll speak more about how we implemented this in the [Router](#Router) section of this post, but most of this was handed using custom route tables on the subnets, a gateway load balancer, and iptables.
## Internet
Team connectivity from the internet was enabled through load-balanced OpenVPN servers in a public subnet. We also had a NAT gateway to easily handle egress internet access from EC2s in our private subnets.

We have two public internet subnets because it is the minimum number required to deploy an application load balancer.

> [!info] V1 Diagram
The complexity increased dramatically as we added more and more into the scope of what we wanted to do. For example, here was the V1 diagram:
![[Pasted image 20240513150030.png]]
# Game server
 The game server we went with was created and documented by the [FAUSTCTF](https://faustctf.net/) team. It is by far the best A/D CTF platform we have seen, and was rock-solid stable for our competition. Check out the [documentation](https://ctf-gameserver.org/) and [source code](https://github.com/fausecteam/ctf-gameserver) for this project. They did a fantastic job, and a lot of the success of **Pls, I Want In** can be attributed to them.

The game server is split into 4 pieces:
## Web interface
The front-end for the game server is a standard Django application. We hosted it using uWSGI in master mode, with 4 processes with 2 threads each.

`uwsgi.ini`
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

This uWSGI process created a unix socket that was reverse-proxied with nginx.

### Caching
The Django application was configured to interface with a local PostgreSQL and memcached. The caching backend we initially chose was was `PyLibMCCache`, but we started seeing a large number of 500 errors even with a tiny amount of traffic. We ran a load test and compared it with the `PyMemcacheCache` backend.

Run #1 was `PyLibMCCache` and Run #2 was `PyMemcacheCache`:

![[Pasted image 20240513154423.png]]

> [!Error]
> `PyLibMCCache` had a nearly 37% failure rate! Switching to `PyMemcacheCache` solved nearly all of our performance issues with the web server.

## Controller

## Checker

## Submission
# OpenVPN

# Router

# Vulnbox

# Pipelining

# Monitoring

# Game day