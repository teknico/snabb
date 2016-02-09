# How to build Snabb lwAFTR

## Fetch the sources

```bash
$ git clone https://github.com/Igalia/snabbswitch.git
```

We're working on merging to upstream snabb; follow the
progress here: https://github.com/Igalia/snabbswitch/issues/215

## Check out the lwaftr development branch:

```bash
$ cd snabbswitch && git checkout lwaftr_starfruit
```

## Build

```bash
$ make
```

That's all!  You'll find a self-contained `snabb-lwaftr` binary in your
current directory that you can copy whereever you like.
