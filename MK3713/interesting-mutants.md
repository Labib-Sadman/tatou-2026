# Interesting mutants — qim_baseline (baseline run, 98 survivors)

The twelve that drove the new tests. Full list in survivors-before.txt;
those still alive after the new tests in survivors-after-verified.txt.


## is_watermark_applicable__mutmut_6
```diff
-    return len(carriers) >= self._LEN_BITS + 8 * 16 + self._MAC_BITS
+    return len(carriers) > self._LEN_BITS + 8 * 16 + self._MAC_BITS
```

## is_watermark_applicable__mutmut_9
```diff
-    return len(carriers) >= self._LEN_BITS + 8 * 16 + self._MAC_BITS
+    return len(carriers) >= self._LEN_BITS + 8 / 16 + self._MAC_BITS
```

## is_watermark_applicable__mutmut_11
```diff
-    return len(carriers) >= self._LEN_BITS + 8 * 16 + self._MAC_BITS
+    return len(carriers) >= self._LEN_BITS + 8 * 17 + self._MAC_BITS
```

## _mac__mutmut_3
```diff
-        key.encode("utf-8"), self._MAC_CONTEXT + ciphertext, hashlib.sha256
+        key.encode("utf-8"), None, hashlib.sha256
```

## _xor_keystream__mutmut_7
```diff
-    counter = 0
+    counter = 1
```

## _xor_keystream__mutmut_8
```diff
-    while len(stream) < len(data):
+    while len(stream) <= len(data):
```

## _xor_keystream__mutmut_17
```diff
-            key_bytes + self._ENC_CONTEXT + counter.to_bytes(4, "big")
+            key_bytes + self._ENC_CONTEXT + counter.to_bytes(5, "big")
```

## _xor_keystream__mutmut_22
```diff
-        counter += 1
+        counter = 1
```

## _quantize__mutmut_4
```diff
-    k = int(round(y / self._STEP))
+    k = int(round(y * self._STEP))
```

## _quantize__mutmut_15
```diff
-        k = k + 1 if y / self._STEP > k else k - 1
+        k = k + 1 if y / self._STEP > k else k + 1
```

## _majority_vote__mutmut_15
```diff
-        voted.append(1 if ones * 2 > repetitions else 0)
+        voted.append(1 if ones * 3 > repetitions else 0)
```

## _majority_vote__mutmut_16
```diff
-        voted.append(1 if ones * 2 > repetitions else 0)
+        voted.append(1 if ones * 2 >= repetitions else 0)
```