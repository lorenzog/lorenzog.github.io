---
title: Embodiment - or Why LLMs Must Physically Engage With The Real World for The Next Leap
description: Large Language Models are amazing but the next step towards an acceptable AGI needs actual interaction with the real world. This will take longer than we think.
tags:
- LLM
- Embodiment
- Robotics
---

One of my first job after uni was in a robotics lab as a software developer. I was funded in part by a research project called "XPERO" that tried to build ‘robots that could learn from experimentation'. The researcher heading the project designed everything top-down, with strict definitions and semantics, boiling it down to a control engineering problem. I wanted to build a bunch of neural networks, connect them to sensors and see how we could create any behaviour based on reinforcement learning. His approach was analytical, having defined the mathematics behind "experience" and relying entirely on human understanding of the problem. Mine was synthetical and very naive (despite the many heated arguments, we've become best friends).

Fast forward nearly 20 years later. Last week everything was abuzz about the new Deepseek-R1 LLM and its abilities to produce apparently excellent results. [Someone](https://www.vellum.ai/blog/the-training-of-deepseek-r1-and-ways-to-use-it?utm_source=direct&utm_medium=none) ([Reddit thread](https://www.reddit.com/r/LLMDevs/comments/1ibhpqw/how_was_deepseekr1_built_for_dummies/)) did a TL;DR of the paper and I was delighted to see how "pure reinforcement learning" was a key feature of this rising star. At this point I can hear many of you going "actually it's more complex than that…." so let me say it now - I am perfectly aware it's Not That Simple™. But, stay with me.

This is the story of a couple of ideas that have been living "rent free" in my head since then:

 1. If we want intelligence (and consciousness!) we can't simulate a "brain" without also taking into account the environment its "body" interacts with.
 2. The most efficient way to evolve this brain-body-environment triad is to let it do it by itself through trial, error, and reinforcement learning.

LLMs just a part of the brain - the one that governs language and, to some extent, memory. It's time to apply the same engineering effort that gave us ChatGPT to the rest of the body.

## Nature-inspired Systems

After that brief experience in robotics and somewhat disillusioned by their rigid approach to understanding the world, I went on to study Evolutionary and Adaptive Systems. I think the name was chosen in a bout of British humour to have the acronym "[EASy](https://www.sussex.ac.uk/research/centres/ai-research-group/)", which was everything but. These years changed my view on life in a manner that still resonates.

 > You're the first human that lands on Mars. You leave the spaceship, look around and see a blob on the ground. You hear a transmission from Earth, the whole planet is holding their breath and anxiously asking "Is there life on Mars?!". What do you do to test this hypothesis?

That quote was the first question our [lecturer](https://en.wikipedia.org/wiki/Inman_Harvey) asked us, on the very first day. The objective was to make us think how to define life. Does it move? Does it grow? Does it respond to stimuli? Does it follow the 4 "F"s - Flight, Freeze, Fight and ...Reproduce? Does it maintain homeostatic equilibrium with the environment? The more you think about it, the harder it gets to pinpoint an exact definition of "life". Viruses move, but they aren't considered alive. Rivers move following a gradient. Mountains "grow" over time. So does cancer.

If we can't all agree on what "life" is, how can we define "intelligence"? If a visitor from the future shows up with a box and says "this is intelligent", how do you test it?

By studying nature-inspired systems, "artificial life", and learning how complex behaviour can emerge from simple configurations, I was convinced that evolution and reinforcement learning are the way to reach true artificial intelligence. The power of reinforcement learning is remarkable - it's a relatively simple concept to explain and can be simulated very easily. And yet it underpins every nervous system.

What do modern-day LLMs have to do with this?

Language models are wonderful at language and language-based reasoning and deduction. They're amazing, in fact. And while this covers a good chunk of how humans interact,  they can't engage with the physical world. Without a trial-and-error, evolving approach to real world engagement, they will never be able to escape their limits, no matter how many GPU we throw at them and how many billions of parameters we can add.

In other words, LLMs lack the ability to **interact with and build their own models of the physical world**.

What is an "evolving approach"? To create LLMs, the researchers put basic models to the test against another, slightly different model to see which one would perform better. The winner would be slightly mutated and put to the test again. This process led to LLMs eventually producing coherent text over a large number of iterations and "tournaments". As this takes place entirely in software, it can be accelerated by adding more GPUs, more hardware, and ultimately more power. However, we can't speed up interaction with the real world - we're limited by the laws of motion, the amount of mass, its inertia, the speed of actuators, the resolution of sensors, and by how long it takes to put it back together once it smashed against the wall.

I believe that to evolve true intelligence, we must create something capable of engaging with the real world, and apply the same mechanism that produced LLMs - reinforcement learning, at a scale.

## LLMs talking to a robot

But, can't we just[^1] plug in a camera and have an LLM direct a robot with language?

Yes and no. You can add a camera and the LLM will tell you what it recognises in the picture. But to have an LLM "guide" a robot, we (humans) still have to program the robot to "understand" the voice commands - turn left, turn right, step ahead, grab the scissors. Herein lies the first problem: when we introduce the human in the loop, we go back to the "Good Old Fashioned AI" days, where we thought we were cleverer than reinforcement learning. There's this beautiful essay called "[The Bitter Lesson](http://www.incompleteideas.net/IncIdeas/BitterLesson.html)" that summarises it very well; the message is that no matter how clever we think we are in our designs, eventually a system left alone to evolve will most likely surpass us. Here's a quote:

 > We have to learn the bitter lesson that building in how we think we think does not work in the long run. The bitter lesson is based on the historical observations that 1) AI researchers have often tried to build knowledge into their agents, 2) this always helps in the short term, and is personally satisfying to the researcher, but 3) in the long run it plateaus and even inhibits further progress, and 4) breakthrough progress eventually arrives by an opposing approach based on scaling computation by search and learning

In other words, By introducing humans in the loop, an evolving system will be limited by our ability to describe the problem and simplify it in understandable chunks.

Years ago I was volunteering in schools to teach robotics to children. One of the first "lessons" involved me standing in front of the class, pretending to be a robot, and the kids had to guide me to make a jam sandwich. I would obey their commands literally. For example "Grab the jam" and "Pick up the knife". But things quickly became complicated and quite hilarious, as I pulled out a large chunk of jam with the knife and dropped half of it on the table, then managed to poke through the bread with the knife, resulting in a jam-kebab and a big mess and lots of laughter. It was funny, and the kids immediately realised they had to be giving me **precise instructions**. Not only that, but they had to think of every possible thing I could do wrong by misinterpreting what they told me. Welcome to robotics, kids.

Imagine an LLM guiding a robot around a room, and most importantly, **understanding what went wrong** when the robot steps over the cat's tail and the poor creature jumps on the curtains and destroys grandma's old lamp as it lands on the table. Now imagine an LLM doing this a million times until it "learns"[^2]. You'll need a million lamps, a million tables, a lot of angry cats and robots that can be rebuilt quickly - and it will still take a very long time. This is engineering at its core - tinker until it works, then figure out why, and optimise.

It's very hard to define "intelligence". Personally, I think it's something like trying to describe the "wetness" of water or the "snowiness" of snow to someone that never experienced it.

If you watch a robot controlled solely through language by an LLM, I can guarantee that you won't call it "intelligent" even after just a few minutes. At best, it will look clunky and funny, at worst, useless and dangerous. I'm not talking about watching a video of military machines dancing in a controlled environment, but trusting a heavy clunk of metal "improvise" in your living room (remove the cat first).

In other words, **without real-world interaction, a mere language model will forever lack the tools not only to become "true AGI", but have a dent in all meaningful parts of society that involve the physical** - farming, elderly and childcare, transportation, manufacturing, and so forth.

## But we have self-driving cars and dog robots and drones.

All the commercial and military robots you see today still follow the "human in the loop" approach. They need to be **reliable**. From cars to drones, they are built as a series of control loops designed top-down, with a lot of "safety controls". Modern robots are conceptually identical to nuclear power plants,  aeroplanes, or chemical plants - a lot of sensors and loops and very precise programming parameters. Everything is predetermined and expected to stay within tolerance, or the system will gracefully stop. This is what we need to know before we board a flight.

It is also the fundamental difference with the "evolving" approach. We **evolved to adapt to any[^3] input our sensors can perceive**, and react based on **likelihood** of neurons firing. That's the key - we evolved alongside our "sensors" (sight, touch, smell, proprioception, etc.) as they, in turn, evolved to deal with the environment that was at hand.

Nobody in their right mind would "evolve" a nuclear power plant that works based on "probabilities". Control engineering has a well-defined role and gave us amazing technological progress; however, it cannot take us to true AGI. We need to stop thinking we're smarter than evolutionary pressure.

I am fully aware that there are plenty of academic projects of "evolving" robots and they are truly fascinating; but none has had any serious engineering effort applied to it. Similarly, reinforcement learning and the ideas behind LLMs have been known in academia for years - but we just didn't have the technology to implement it on a large scale.

Now it is the time to apply our engineering efforts to these research projects - to make evolutionary robotics resilient and allowing for quick iterations, much like the Wright brothers did when they were building their aeroplane prototypes. The next startup that will bring this to market will make billions.

Robotics is hard. Sensors, inputs, force feedback even more so. While it's nice we can live a lot of our lives in a digital virtual world of software, abstract ideas and mobile apps, for AI to truly impact our way of life we need to let it play with the "real" world and its complexities.

## Conclusions

Reinforcement learning and evolutionary algorithms, coupled with the right amount of computing power have brought us LLMs. If we want to take this concept and bring it to the next level, we must find how to apply it to the physical world - to bring embodiment into the picture - without mandating our human-centered view of "how it should work". We need a self-correcting, reinforcement loop directly engaging with the physical. We need to put a "brain" into a "body" and let them engage with the "environment", in a guided fashion first.

If you ever engaged with babies, this might sound very familiar.

[^1]: Every time I see "just" in a sentence, my reaction is to think "you don't understand the complexity of what you're talking about". It's never, ever "just". 

[^2]: Don't hurt any cats, please.

[^3]: While it is true that our bodies require certain conditions to function, they do not need their "inputs" to be precisely defined. We use homeostasis to maintain working conditions - perhaps this can be defined as a very complex control loop, but at an organism level that's an oversimplification.
