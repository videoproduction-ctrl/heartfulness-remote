HEARTFULNESS REMOTE FOR THE MAC YOU WANT TO CONTROL
====================================================

This folder contains two things:
  - Heartfulness Remote      (the app)
  - README-FIRST.txt         (this note)


1. PUT THE APP IN APPLICATIONS
------------------------------
Open a new Finder window, click "Applications" in the sidebar, then drag
"Heartfulness Remote" from this folder into the Applications window.

(If you forget, the app offers to move itself the first time you open it.)


2. OPEN IT THE FIRST TIME
-------------------------
Double-click "Heartfulness Remote" in Applications.

The first time, macOS says it cannot check the app. That is expected: the app
is signed for your own use, not by Apple. To open it anyway:

  a. Click "Done" in that message.
  b. Open the Apple menu > System Settings > Privacy & Security.
  c. Scroll down. Next to "Heartfulness Remote was blocked..." click
     "Open Anyway", then confirm with your Mac password or Touch ID.

You only need to do this once (and again after installing an update).


3. FOLLOW THE SETUP WINDOW
--------------------------
A setup window opens and guides you, one step at a time:

  - Type your server address (for example heartfulness-remote.duckdns.org).
  - Allow "Screen Recording" and "Accessibility" when macOS asks. These let
    your approved devices see the screen and use the mouse and keyboard.
  - Turn on the firewall (macOS asks for your Mac password once).
  - Pair your phone by pointing its camera at the code on the screen.

Heartfulness Remote then lives in the menu bar at the top right of the
screen. Its icon shows the status:
  - a small screen ........ ready, nobody connected
  - a person with "!" ..... someone is connected (an orange banner shows too)
  - a raised hand ......... all connections are blocked
  - Wi-Fi with a slash .... not connected to your server


STOP EVERYTHING AT ONCE
-----------------------
Press Control + Option + Command + K on the keyboard, or click the menu bar
icon and switch on "Block all connections".


AFTER AN UPDATE
---------------
Replace the old app in Applications with the new one. macOS may ask you to
allow Screen Recording and Accessibility again; the app shows you how.
If Heartfulness Remote is already switched on in those lists, switch it off
and on again.


More help: see USER-GUIDE.md in the project, or the "Fix offline" section.
