# QIRA

[![Build Status](https://travis-ci.org/geohot/qira.svg?branch=master)](https://travis-ci.org/geohot/qira)

* QIRA is a competitor to strace and gdb
* See http://qira.me/ for high level usage information
* All QIRA code is released under MIT license
* Other code in this repo released under its respective license

## Supported OS

<pre>
Ubuntu 14.04 and 16.04 supported out of the box.
18.04 and 20.x is having a problem with building QEMU
See forked QEMU source at https://github.com/geohot/qemu/tree/qira to fix.

Non Linux hosts may run the rest of QIRA, but cannot run the QEMU tracer.
Very limited support for Mac OS X and Windows natively.
The Docker image in docker should work everywhere.
</pre>

## Installing release

See instructions on [qira.me](http://qira.me/) to install 1.3

## Installing trunk

<pre>
cd ~/
git clone https://github.com/geohot/qira.git
cd qira/
./install.sh
</pre>

### Docker
<pre>
cd ~/
git clone https://github.com/geohot/qira.git
cd qira/docker
./build.sh
</pre>

Run: <pre>sudo docker run -p 3302:3302 -it qira bash
qira _target_</pre>

Then, connect to __localhost:3002__

If you want to copy a file from your filesystem to the container launch: <pre>sudo docker cp _source_ _container_name_:_path_ </pre>

## Installation Extras

* ./fetchlibs.sh will fetch the libraries for i386, armhf, armel, aarch64, mips, mipsel, and ppc
* ./tracers/pin_build.sh will install the QIRA PIN plugin, allowing --pin to work


## Releases

* v1.3 -- Update using pinned python packages
* v1.2 -- Many many changes. Forced release due to v1.0 not working anymore.
* v1.1 -- Support for names and comments. Static stuff added. Register colors.
* v1.0 -- Perf is good! Tons of bugfixes. Quality software. http://qira.me/
* v0.9 -- Function indentation. haddrline added (look familiar?). Register highlighting in hexdump.
* v0.8 -- Intel syntax! Shipping CDA (cda a.out) and experimental PIN backend. Bugfixes. Windows support?
* v0.7 -- DWARF support. Builds QEMU if distributed binaries don't work. Windows IDA plugin.
* v0.6 -- Added changes before webforking. Highlight strace addresses. Default on analysis.
* v0.5 -- Fixed regression in C++ database causing wrong values. Added PowerPC support. Added "A" button.
* v0.4 -- Using 50x faster C++ database. strace support. argv and envp are there.
* v0.3 -- Built in socat, multiple traces, forks (experimental). Somewhat working x86-64 and ARM support
* v0.2 -- Removed dependency on mongodb, much faster. IDA plugin fixes, Mac version.
* v0.1 -- Initial release


## UI

<pre>
At the top, you have 4 boxes, called the controls.
  Blue = change number, grey = fork number
  red = instruction address (iaddr), yellow = data address (daddr).

On the left you have the vtimeline, this is the full trace of the program.
  The top is the start of the program, the bottom is the end/current state.
  More green = deeper into a function.
  The currently selected change is blue, red is every passthrough of the current iaddr
  Bright yellow is a write to the daddr, dark yellow is a read from the daddr.
  This color scheme is followed everywhere.

Below the controls, you have the idump, showing instructions near the current change
Under that is the regviewer, datachanges, hexeditor, and strace, all self explanatory.
</pre>


## Mouse Actions
Click on vtimeline to navigate around. Right-click forks to delete them. Click on data (or doubleclick if highlightable) to follow in data. Right-click on instruction address to follow in instruction.

## Keyboard Shortcuts in web/client/controls.js
<pre>
j -- next invocation of instruction
k -- prev invocation of instruction

shift-j -- next toucher of data
shift-k -- prev toucher of data

m -- go to return from current function
, -- go to start of current function

z -- zoom out max on vtimeline

left  -- -1 fork
right -- +1 fork
up    -- -1 clnum
down  -- +1 clnum

esc -- back

shift-c -- clear all forks

n -- rename instruction
shift-n -- rename data
: -- add comment at instruction
shift-: -- add comment at data

g -- go to change, address, or name
space -- toggle flat/function view

p -- analyze function at iaddr
c -- make code at iaddr, one instruction
a -- make ascii at iaddr
d -- make data at iaddr
u -- make undefined at iaddr
</pre>

## Installation on Windows (experimental)

* Install git and python 2.7.9
* Run install.bat


## Session state
<pre>
clnum -- selected changelist number
forknum -- selected fork number
iaddr -- selected instruction address
daddr -- selected data address

cview -- viewed changelists in the vtimeline
dview -- viewed window into data in the hexeditor
iview -- viewed address in the static view

max_clnum -- max changelist number for each fork
dirtyiaddr -- whether we should update the clnum based on the iaddr or not
flat -- if we are in flat view
</pre>


## Static

QIRA static has historically been such a trash heap it's gated behind -S. QIRA should not be trying to compete with IDA.

User input and the actual traces of the program should drive creation of the static database. Don't try to recover all CFGs, only what ran.

The basic idea of static is that it exists at change -1 and doesn't change ever. Each address has a set of tags, including things like name.

