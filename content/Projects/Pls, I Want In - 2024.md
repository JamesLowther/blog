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

About 8 months ago, me and a group of friends decided to take a stab at developing our own attack-defence CTF. For me, this was something far more complicated than anything I had done before. Many of us on the team have previous experience hosting jeopardy-style CTFs before, but the dynamic nature of AD CTFs was daunting. Nevertheless, we started development in September 2023, and held the first iteration of **Pls, I Want In** on May 11th, 2024.

This post will outline the successes and challenges we faced developing **Pls, I Want In**, while diving deep into the technical nitty-gritty that we had to learn in order to run the competition.

# What is an attack-defence CTF
An attack-defence (AD) CTF is a unique form of cybersecurity competition where teams are given identical vulnerable servers (vulnboxes) which contain application code with intentionally placed vulnerabilities. These services are often HTTP-based, such as web services, or TCP-based, which have a CLI interface that can be accessed with tools like netcat. Each service contains common security vulnerabilities such as SQL-injections, SSRFs, template-injections, buffer-overflows, and many more.

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

This [video by LiveOverflow](https://www.youtube.com/watch?v=RkaLyji9pNs) provides a more illustrative example of how the game works.
# Development goals
When we first started talking about the prospect of actually building an attack-defence CTF, the following goals were identified:

1. Create the infrastructure and services for a small-scale attack-defence CTF suitable for beginners.
2. Create a vulnbox that will have 1-3 services, and can be played within 3-4 hours.
3. Hosted in AWS using cloud-native practices, implementing scaling where we can.
4. Creating good documentation and architecture diagrams.
5. Everything as code, and as much automation as we can.
6. Pipelined as much as we can.
7. Monitoring, such as metric/log collection, as much as we can.
8. Do it as cost-effective as possible, within reason.

I pushed for developing the competition using AWS, because it is the cloud provider that I have the most professional experience in. I wanted to take this opportunity to improve my knowledge of cloud best-practices, such as infrastructure scaling. I wanted the infrastructure to be suitable to competitions of many sizes, allowing it to easily be scaled out to support larger competitions.

As you will see in the remainder of this post, some of these goals we were very successful in completing, and others... not so much. 

