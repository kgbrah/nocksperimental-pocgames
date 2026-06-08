::  Forfeit Dice Kernel — provably-fair two-sided commit-reveal dice (even money)
::
::  Game 2. Same trustless commit-reveal core as forfeit-flip.hoon, but the outcome is a
::  uniform roll in 0..9999 compared to a FIXED 50/50 line (5000). The roll is published,
::  so the distribution can be proven uniform off-chain (chi-square over many rounds) — the
::  distinct forensic capability vs the single-bit flip.
::
::  WHY THE LINE IS FIXED: this is an EVEN-MONEY 2-outcome wager. A player-chosen line
::  would change the odds (and an outcome-conditional / multiplied payout is inexpressible
::  on Nockchain consensus). The line is therefore a fixed kernel constant; what varies and
::  is proven is that the roll is UNIFORM over the whole range.
::
::  PROVABLE FAIRNESS (identical to forfeit-flip): commit-house=(shax serverSeed),
::  commit-player=(shax clientSeed), both poked before reveal; the kernel never holds an
::  unrevealed seed (commit-only peek surface). At %reveal the hashlocks are checked, then:
::    base = (shax (jam [serverSeed clientSeed nonce]))
::    roll = REJECTION-SAMPLED reduction of base into 0..9999 (kills modulo bias on the
::           non-power-of-2 modulus); the kernel publishes rejection-index for auditability.
::    player wins iff (gte roll 5.000).
::
/+  lib
/=  *  /common/wrapper
::
=>  |%
+$  commit  @
+$  seed    @
+$  round
  $:  nonce=@ud
      commit-house=(unit commit)
      commit-player=(unit commit)
      reveal-house=(unit seed)
      reveal-player=(unit seed)
      roll=(unit @ud)                 :: uniform 0..9999, set at reveal (public)
      rejection-index=(unit @ud)      :: # of rejection-sampling retries (audit)
      outcome=(unit ?)                :: %.y = player wins (roll >= line)
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
  $%  [%commit hash=commit]
      [%client-commit hash=commit]
      [%reveal server=seed client=seed]
      [%new-round ~]
  ==
--
|%
::  Fixed, transparent game parameters.
++  line  5.000                       :: the 50/50 threshold; player wins iff roll >= line
++  modulus  10.000                    :: roll range is 0..9999
++  moat  (keep versioned-state)
::
++  fresh-round
  |=  n=@ud
  ^-  round
  [n ~ ~ ~ ~ ~ ~ ~]
::
::  Rejection-sample a uniform value in 0..modulus-1 from a 256-bit seed hash. Returns the
::  roll plus the number of retries. Rejection is astronomically rare (modulus / 2^256), but
::  doing it makes the uniform distribution provable rather than approximate.
++  sample-roll
  |=  base=@
  ^-  [roll=@ud idx=@ud]
  =/  limit  (mul (div (bex 256) modulus) modulus)
  =+  [h=base rejected=0]
  |-  ^-  [roll=@ud idx=@ud]
  ?:  (lth h limit)
    [(mod h modulus) rejected]
  $(h (shax (jam [h rejected])), rejected +(rejected))
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
    ::  Commitments, nonce, fixed line, and post-reveal data ONLY — never an unrevealed seed.
    ?+  path  ~
      [%nonce ~]
    ``nonce.current.state
      [%line ~]
    ``line
      [%commit-house ~]
    ``commit-house.current.state
      [%commit-player ~]
    ``commit-player.current.state
      [%roll ~]
    ``roll.current.state
      [%rejection-index ~]
    ``rejection-index.current.state
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
      :_  state(current cur(commit-house `hash.u.c))
      ~[[%log 'house commit recorded']]
    ::
        %client-commit
      ?:  ?=(~ commit-house.cur)
        :_  state
        ~[[%log 'house must commit first']]
      ?.  ?=(~ commit-player.cur)
        :_  state
        ~[[%log 'player already committed']]
      :_  state(current cur(commit-player `hash.u.c))
      ~[[%log 'player commit recorded']]
    ::
        %reveal
      ?.  ?&(?=(^ commit-house.cur) ?=(^ commit-player.cur))
        :_  state
        ~[[%log 'both parties must commit before reveal']]
      ?.  ?=(~ outcome.cur)
        :_  state
        ~[[%log 'round already resolved']]
      ?.  =(u.commit-house.cur (shax server.u.c))
        :_  state
        ~[[%log 'server seed does not match house commitment']]
      ?.  =(u.commit-player.cur (shax client.u.c))
        :_  state
        ~[[%log 'client seed does not match player commitment']]
      =/  base  (shax (jam [server.u.c client.u.c nonce.cur]))
      =/  sample  (sample-roll base)
      =/  player-wins  (gte roll.sample line)
      =/  new-cur
        %=  cur
          reveal-house     `server.u.c
          reveal-player    `client.u.c
          roll             `roll.sample
          rejection-index  `idx.sample
          outcome          `player-wins
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
