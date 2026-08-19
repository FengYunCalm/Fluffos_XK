#!/usr/bin/env python3
"""#1247 C-S2: generate the fixed representative LPC compile corpus.

Deterministic (fixed seed): 10 templates x 10 variants = 100 files,
each 100-200 lines, covering string literals, arrays, mappings, macros,
functions, switch, loops, object patterns and mixed constructs.
No #include lines (bench_compile drives compile_file() directly, which
resolves relative includes against the file's own directory only).

Regenerate with: python3 tools/perf/gen_compile_corpus.py
"""
import os
import random

OUT = os.path.join(os.path.dirname(__file__), "corpus")
SEED = 20260819
VARIANTS = 10

TEMPLATES = {
    "s_strings": """\
// representative: string literals, escapes, concatenation
string make_greeting_{v}(string name) {{
  string a = "Hello, " + name + "!\\n";
  string b = "tab\\there and \\"quotes\\" and \\\\backslash\\\\";
  string c = "\\x41\\x42\\x43 octal \\101\\102\\103";
  string d = "line one\\nline two\\nline three\\n";
  string e = "unicode \\u4e2d\\u6587 and \\U0001F600 emoji";
  string f = "the quick brown fox jumps over the lazy dog";
  string g = "pack my box with five dozen liquor jugs";
  string h = "how vexingly quick daft zebras jump";
  string i = "sphinx of black quartz, judge my vow";
  string j = "the five boxing wizards jump quickly";
  return a + b + c + d + e + f + g + h + i + j;
}}
string repeat_{v}(string s, int n) {{
  string out = "";
  for (int i = 0; i < n; i++) out += s;
  return out;
}}
string concat_many_{v}(string *parts) {{
  string out = "";
  for (int i = 0; i < sizeof(parts); i++) out += parts[i] + "|";
  return out;
}}
string format_row_{v}(string name, int score) {{
  return sprintf("%-20s %8d", name, score);
}}
""",
    "s_arrays": """\
// representative: array construction and indexing
int sum_array_{v}(int *arr) {{
  int total = 0;
  for (int i = 0; i < sizeof(arr); i++) total += arr[i];
  return total;
}}
int *build_array_{v}(int n) {{
  int *out = allocate(n);
  for (int i = 0; i < n; i++) out[i] = i * i + {v};
  return out;
}}
int *slice_{v}(int *arr, int lo, int hi) {{
  if (lo < 0) lo = 0;
  if (hi >= sizeof(arr)) hi = sizeof(arr) - 1;
  return arr[lo..hi];
}}
""",
    "s_mappings": """\
// representative: mapping literals and access
mapping build_index_{v}(string *keys, int *vals) {{
  mapping m = ([]);
  for (int i = 0; i < sizeof(keys); i++) m[keys[i]] = vals[i] + {v};
  return m;
}}
int lookup_{v}(mapping m, string key) {{
  if (undefinedp(m[key])) return -1;
  return m[key];
}}
mapping merge_{v}(mapping a, mapping b) {{
  mapping out = ([]);
  foreach (string k, int val in a) out[k] = val;
  foreach (string k, int val in b) out[k] = val;
  return out;
}}
""",
    "s_macros": """\
// representative: macro expansion
#define MAX_{v}(a, b) ((a) > (b) ? (a) : (b))
#define MIN_{v}(a, b) ((a) < (b) ? (a) : (b))
#define SQUARE_{v}(x) ((x) * (x))
#define CUBE_{v}(x) (SQUARE_{v}(x) * (x))
#define LIMIT_{v} {limit}
#define TWICE_{v}(x) (SQUARE_{v}(x) + SQUARE_{v}(x))
#define THRICE_{v}(x) (CUBE_{v}(x) + SQUARE_{v}(x) + (x))
#define CLAMP_{v}(x, lo, hi) ((x) < (lo) ? (lo) : ((x) > (hi) ? (hi) : (x)))
#define SUM3_{v}(a, b, c) ((a) + (b) + (c))
#define PROD3_{v}(a, b, c) ((a) * (b) * (c))

int use_macros_{v}(int a, int b) {{
  int m = MAX_{v}(a, b);
  int s = SQUARE_{v}(m);
  s = TWICE_{v}(s);
  s = THRICE_{v}(s);
  s = CLAMP_{v}(s, 0, LIMIT_{v});
  s = SUM3_{v}(s, MIN_{v}(a, b), PROD3_{v}(a, b, 2));
  if (s > LIMIT_{v}) s = LIMIT_{v};
  return s;
}}
""",
    "s_functions": """\
// representative: many small functions, default args, varargs
int add_{v}(int a, int b) {{ return a + b; }}
int sub_{v}(int a, int b) {{ return a - b; }}
int mul_{v}(int a, int b) {{ return a * b; }}
int div_{v}(int a, int b) {{ return b ? a / b : 0; }}
int mod_{v}(int a, int b) {{ return b ? a % b : 0; }}
int neg_{v}(int a) {{ return -a; }}
int abs_{v}(int a) {{ return a < 0 ? -a : a; }}
int clamp_{v}(int a, int lo, int hi) {{ return a < lo ? lo : (a > hi ? hi : a); }}
int sum3_{v}(int a, int b, int c) {{ return a + b + c; }}
int sum_varargs_{v}(mixed *args...) {{
  int t = 0;
  for (int i = 0; i < sizeof(args); i++) t += args[i];
  return t;
}}
""",
    "s_switch": """\
// representative: switch dispatch
string classify_{v}(int code) {{
  switch (code) {{
    case 0: return "zero";
    case 1: case 2: case 3: return "small";
    case 10..20: return "teens";
    case 100: return "hundred";
    case {vplus}: return "variant";
    default: return "other";
  }}
}}
int dispatch_{v}(int code) {{
  switch (code) {{
    case 0: return 0;
    case 1: return 1;
    case 2: return 4;
    case 3: return 9;
    case 4: return 16;
    case 5: return 25;
    default: return -1;
  }}
}}
""",
    "s_loops": """\
// representative: nested loops and conditionals
int count_primes_{v}(int limit) {{
  int count = 0;
  for (int i = 2; i < limit; i++) {{
    int prime = 1;
    for (int j = 2; j * j <= i; j++) {{
      if (i % j == 0) {{ prime = 0; break; }}
    }}
    if (prime) count++;
  }}
  return count + {v};
}}
int sum_squares_{v}(int n) {{
  int total = 0;
  int i = 0;
  while (i < n) {{
    total += i * i;
    i++;
  }}
  return total;
}}
""",
    "s_objects": """\
// representative: object creation, apply patterns
object make_room_{v}(string name, string *exits) {{
  object room = new("/std/room");
  room->set_name(name);
  for (int i = 0; i < sizeof(exits); i++) {{
    room->add_exit(exits[i], "/world/void");
  }}
  return room;
}}
int has_exit_{v}(object room, string dir) {{
  return !undefinedp(room->query_exit(dir));
}}
string describe_{v}(object ob) {{
  return ob->short() + " (" + ob->query_name() + ")";
}}
""",
    "s_mixed": """\
// representative: mixed constructs, closures, sscanf
varargs string format_entry_{v}(mapping entry, int verbose) {{
  string name = entry["name"];
  int level = entry["level"];
  string out = sprintf("%s (level %d)", name, level);
  if (verbose) out += sprintf(" hp=%d mp=%d", entry["hp"], entry["mp"]);
  return out;
}}
int parse_coords_{v}(string line) {{
  int x, y;
  if (sscanf(line, "%d,%d", x, y) == 2) return x * 1000 + y;
  return -1;
}}
int apply_twice_{v}(function f, int x) {{
  return (*f)((*f)(x));
}}
""",
    "s_classes": """\
// representative: class definitions and access
class point_{v} {{
  int x;
  int y;
  string label;
}}
class point_{v} make_point_{v}(int x, int y) {{
  class point_{v} p = new(class point_{v});
  p->x = x;
  p->y = y;
  p->label = sprintf("(%d,%d)", x, y);
  return p;
}}
int dist2_{v}(class point_{v} p) {{
  return p->x * p->x + p->y * p->y;
}}
""",
}


def main():
    rng = random.Random(SEED)
    os.makedirs(OUT, exist_ok=True)
    for name, tmpl in sorted(TEMPLATES.items()):
        for v in range(VARIANTS):
            limit = rng.randint(50, 500)
            vplus = v + 1000
            body = tmpl.format(v=v, vplus=vplus, limit=limit)
            # pad to 100-200 lines with harmless declarations
            extra = []
            for i in range(100 - body.count("\n")):
                extra.append("int pad_{}_{} = {};".format(v, i, rng.randint(0, 1000)))
            content = body + "\n".join(extra) + "\n"
            with open(os.path.join(OUT, "{}_{:02d}.c".format(name, v)), "w") as f:
                f.write(content)
    total = sum(len(fn) for fn in os.listdir(OUT) if fn.endswith(".c"))
    print("generated {} files, {} bytes in {}".format(len(os.listdir(OUT)), total, OUT))


if __name__ == "__main__":
    main()
