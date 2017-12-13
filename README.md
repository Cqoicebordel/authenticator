# Authenticator

## Demo

http://www.cqoicebordel.net/authenticator/demo/

## What is it ?

It's a webapp allowing you to see your TOTP (two factors authentication) codes easily.

## How does it work ?

Everything is done locally, with JS. No network necessary, and moreover, no network request done at all. You don't even need a webserver to use it on your computer. It's more or less secure.

## How to use it ?

* Download the repository however you like. As a zip works well.
* Extract in your wanted folder.
* Fill the settings.js with the secrets of your TOTP accounts, and their names.
* Open index.html

To have the secrets, you either go to each site to ask for one, or if you have a rooted Android phone, with the Google Authenticator App, you can open the /data/data/com.google.android.apps.authenticator2/databases/databases file, which contains all the accounts with their secrets.

## What is its purpose ?

It was kind of cumbersome to open the right app in my phone each time I wanted to log in, and my PC is only used by me, in my home (a desktop). So it was secure to have those codes on that machine. And doing it, I found out that it was perfect to use in a Vivaldi web panel.

## How was it build ?

This project was hacked together in a couple of days, copy/pasting a lot of code. So I have a lot of acknowledgments to do.
* First, I started with https://github.com/qoomon/google-authenticator-webapp, I removed all the QRCode things, fixed a couple of bugs (the hexToDec for example), removed all unnecessary CSS (removing the dependancy to bootstrap), removed all unnecessary JS, removed the animations that were a performance hog, made it dynamic to follow the settings.js file, added a tiny bit of accessibility, etc.
* Doing so, I used a few library that I stripped as most as possible (including the libs that were in the original project) :
	* https://kimmobrunfeldt.github.io/progressbar.js/ for the circle progress bar
	* http://caligatio.github.com/jsSHA/ for calculating the SHA (note that only v1.6.0 seems to work. I didn't investigate why : it works :) )
	* A tiny bit of code from https://github.com/nextcloud/passman for doing a better TOTP algorithm
	* https://gist.github.com/ghalimi/4525548 for correcting a bug
* Used icon from https://www.iconfinder.com/icons/87859/authenticator_icon#size=128

## What not to do with this ?

* Don't host it on an Internet accessible page.
* Don't use it on a laptop : if someone steal this, or you lose it, they will have your passwords, *and* your 2 factors auth codes too.
* Don't use it on a multi-users computer.
And I'm not a security expert, so, be very, very, very careful with it.

## What is the licence ?

My work is published under the WTFPL. Beware that it covers only my work, and I didn't double check the licences of the other stuff I used.

## Is it secure ?

It doesn't do any network request (beyond loading, of course). So I won't stole your codes that way. Beyond that, I'm not a security expert. Please be careful with your secrets. I'm not responsible for anything bad that could happen. This project is provided as-is.
