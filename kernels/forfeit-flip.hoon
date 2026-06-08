::  Forfeit Flip Kernel — provably-fair two-sided commit-reveal coinflip
::
::  The corrected, un-cheatable successor to coinflip.hoon. It is a deterministic
::  REFEREE (it holds no funds — settlement is an on-chain HTLC escrow, off-kernel).
::
::  WHY IT CANNOT BE PEEK-CHEATED (the coinflip.hoon bug, fixed structurally):
::  coinflip.hoon stored the secret `seed` in state and exposed it via `[%state ~]`,
::  so a player peeked the seed and predicted the flip. Forfeit Flip NEVER holds an
::  unrevealed seed: the house and player each poke only a COMMITMENT (a hash of their
::  secret). The kernel learns a seed only at %reveal — i.e. when it is already public.
::  So there is no secret in peekable state to leak.
::
::  PROVABLE FAIRNESS (two-sided commit-reveal):
::    commit-house   = (shax serverSeed)            poked before any bet
::    commit-player  = (shax clientSeed)            poked before the house reveals
::    outcome        = (mod (shax (jam [serverSeed clientSeed nonce])) 2)
::                       0 = house wins, 1 = player wins
::    %reveal verifies (shax serverSeed)==commit-house AND (shax clientSeed)==commit-player
::    so a post-hoc grind fails the hashlock; neither party can predict (each commits
::    before seeing the other's seed) nor bias the result.
::
/+  lib
/=  *  /common/wrapper
::
=>  |%
+$  commit  @                        :: a hash commitment to a secret seed
+$  seed    @                        :: a revealed secret seed
+$  round
  $:  nonce=@ud
      commit-house=(unit commit)
      commit-player=(unit commit)
      reveal-house=(unit seed)
      reveal-player=(unit seed)
      outcome=(unit ?)               :: %.y = player wins, %.n = house wins
  ==
+$  state  [current=round next-nonce=@ud history=(list round)]
+$  versioned-state
  $:  %v1
      state
  ==
+$  effect
  $%  [%log msg=@t]
  ==
+$  cause
  $%  [%commit hash=commit]          :: house commits (shax serverSeed)
      [%client-commit hash=commit]   :: player commits (shax clientSeed)
      [%reveal server=seed client=seed]
      [%new-round ~]
  ==
--
|%
++  moat  (keep versioned-state)
::
++  fresh-round
  |=  n=@ud
  ^-  round
  [n ~ ~ ~ ~ ~]
::
++  inner
  |_  state=versioned-state
  ::
  ++  load
    |=  old-state=versioned-state
    ^-  versioned-state
    old-state
  ::
  ++  peek
    |=  =path
    ^-  (unit (unit *))
    ::  PEEK SURFACE: commitments, nonce, and post-reveal data ONLY.
    ::  There is deliberately NO path that returns an unrevealed seed — the kernel
    ::  never holds one. This is the structural fix for the coinflip.hoon seed leak.
    ?+  path  ~
      [%nonce ~]
    ``nonce.current.state
      [%commit-house ~]
    ``commit-house.current.state
      [%commit-player ~]
    ``commit-player.current.state
      [%outcome ~]
    ``outcome.current.state
      [%round ~]
    ``current.state
    ==
  ::
  ++  poke
    |=  =ovum:moat
    ^-  [(list effect) versioned-state]
    =/  c  ((soft cause) cause.input.ovum)
    ?~  c
      :_  state
      ~[[%log 'invalid cause']]
    =/  cur  current.state
    ?-  -.u.c
    ::
        %commit
      ?.  ?=(~ commit-house.cur)
        :_  state
        ~[[%log 'house already committed']]
      =/  new-cur  cur(commit-house `hash.u.c)
      :_  state(current new-cur)
      ~[[%log 'house commit recorded']]
    ::
        %client-commit
      ?:  ?=(~ commit-house.cur)
        :_  state
        ~[[%log 'house must commit first']]
      ?.  ?=(~ commit-player.cur)
        :_  state
        ~[[%log 'player already committed']]
      =/  new-cur  cur(commit-player `hash.u.c)
      :_  state(current new-cur)
      ~[[%log 'player commit recorded']]
    ::
        %reveal
      ?.  ?&(?=(^ commit-house.cur) ?=(^ commit-player.cur))
        :_  state
        ~[[%log 'both parties must commit before reveal']]
      ?.  ?=(~ outcome.cur)
        :_  state
        ~[[%log 'round already resolved']]
      ::  hashlock check: the revealed seeds MUST match the prior commitments.
      ?.  =(u.commit-house.cur (shax server.u.c))
        :_  state
        ~[[%log 'server seed does not match house commitment']]
      ?.  =(u.commit-player.cur (shax client.u.c))
        :_  state
        ~[[%log 'client seed does not match player commitment']]
      =/  out-hash  (shax (jam [server.u.c client.u.c nonce.cur]))
      =/  player-wins  =(1 (mod out-hash 2))
      =/  new-cur
        %=  cur
          reveal-house    `server.u.c
          reveal-player   `client.u.c
          outcome         `player-wins
        ==
      :_  state(current new-cur)
      :~  [%log ?:(player-wins 'resolved: PLAYER wins' 'resolved: HOUSE wins')]
      ==
    ::
        %new-round
      ?:  ?=(~ outcome.cur)
        :_  state
        ~[[%log 'cannot start a new round before the current one resolves']]
      =/  n  next-nonce.state
      =/  new-state
        %=  state
          history     [cur history.state]
          current     (fresh-round n)
          next-nonce  +(n)
        ==
      :_  new-state
      ~[[%log 'new round started']]
    ==
  --
--
((moat |) inner)
