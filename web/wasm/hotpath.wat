;; Darlene-X_2.0 hot-path WASM helpers (no WASI / no imports)
;; Exports:
;;   memory
;;   unique_bytes(len) -> i32   how many distinct byte values in [0,len)
;;   xor_fold(len) -> i32       fast rolling checksum
;;   packed_score(len) -> i32   0-100 packing heuristic (high => compressed/encrypted)

(module
  (memory (export "memory") 256)

  ;; unique_bytes(len) -> i32
  (func (export "unique_bytes") (param $len i32) (result i32)
    (local $i i32)
    (local $b i32)
    (local $count i32)

    (if (i32.eqz (local.get $len)) (then (return (i32.const 0))))

    ;; clear 256-byte presence map at 1MiB
    (memory.fill (i32.const 0x100000) (i32.const 0) (i32.const 256))

    (local.set $i (i32.const 0))
    (block $end_scan
      (loop $scan
        (br_if $end_scan (i32.ge_u (local.get $i) (local.get $len)))
        (local.set $b (i32.load8_u (local.get $i)))
        (i32.store8 (i32.add (i32.const 0x100000) (local.get $b)) (i32.const 1))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)
      )
    )

    (local.set $count (i32.const 0))
    (local.set $i (i32.const 0))
    (block $end_count
      (loop $count_loop
        (br_if $end_count (i32.ge_u (local.get $i) (i32.const 256)))
        (if (i32.load8_u (i32.add (i32.const 0x100000) (local.get $i)))
          (then (local.set $count (i32.add (local.get $count) (i32.const 1))))
        )
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $count_loop)
      )
    )
    (local.get $count)
  )

  ;; xor_fold(len) -> i32
  (func (export "xor_fold") (param $len i32) (result i32)
    (local $i i32)
    (local $acc i32)
    (local.set $acc (i32.const 0))
    (local.set $i (i32.const 0))
    (block $end
      (loop $loop
        (br_if $end (i32.ge_u (local.get $i) (local.get $len)))
        (local.set $acc
          (i32.xor (local.get $acc) (i32.load8_u (local.get $i))))
        (local.set $acc
          (i32.add
            (i32.rotl (local.get $acc) (i32.const 5))
            (i32.const 0x9e3779b9)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)
      )
    )
    (local.get $acc)
  )

  ;; packed_score(len) -> i32 in 0..100
  ;; Uses unique_bytes: near-256 => likely packed/encrypted; low => structured.
  (func (export "packed_score") (param $len i32) (result i32)
    (local $u i32)
    (local $score i32)
    (if (i32.lt_u (local.get $len) (i32.const 64)) (then (return (i32.const 0))))
    (local.set $u (call $unique_bytes_internal (local.get $len)))
    ;; score = clamp( (u - 80) * 100 / 176 , 0, 100)
    (if (i32.le_u (local.get $u) (i32.const 80))
      (then (return (i32.const 0))))
    (local.set $score
      (i32.div_u
        (i32.mul (i32.sub (local.get $u) (i32.const 80)) (i32.const 100))
        (i32.const 176)))
    (if (i32.gt_u (local.get $score) (i32.const 100))
      (then (return (i32.const 100))))
    (local.get $score)
  )

  ;; internal copy of unique_bytes for packed_score (avoid export call quirks)
  (func $unique_bytes_internal (param $len i32) (result i32)
    (local $i i32)
    (local $b i32)
    (local $count i32)
    (memory.fill (i32.const 0x100000) (i32.const 0) (i32.const 256))
    (local.set $i (i32.const 0))
    (block $end_scan
      (loop $scan
        (br_if $end_scan (i32.ge_u (local.get $i) (local.get $len)))
        (local.set $b (i32.load8_u (local.get $i)))
        (i32.store8 (i32.add (i32.const 0x100000) (local.get $b)) (i32.const 1))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)
      )
    )
    (local.set $count (i32.const 0))
    (local.set $i (i32.const 0))
    (block $end_count
      (loop $count_loop
        (br_if $end_count (i32.ge_u (local.get $i) (i32.const 256)))
        (if (i32.load8_u (i32.add (i32.const 0x100000) (local.get $i)))
          (then (local.set $count (i32.add (local.get $count) (i32.const 1))))
        )
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $count_loop)
      )
    )
    (local.get $count)
  )
)
