# FluffOS (fork)

English | [简体中文](README_CN.md)

This repository is a fork of FluffOS focused on build reliability and compiler warning cleanup for modern toolchains,
with special attention to Windows/MSYS2 installations.

## Repository Role

- Keeps source-level FluffOS fork changes used by downstream MUD runtime trees
- Focuses on build reliability and targeted compiler cleanup rather than feature divergence
- Tracks upstream separately from the game repositories that consume the driver

## What this fork changes

- **Windows install reliability**: `cmake --install` uses `bash cp -f` to overwrite binaries safely and avoid “Permission denied” when replacing `driver.exe` and related tools.
- **Core warning cleanup**: targeted fixes in scratchpad, preprocessor, ed, telnet_ext, external, and socket_efuns.
- **Third-party warning control**: warning suppression and IPO disabled where needed in libevent/crypt/libwebsockets; filesystem CMake minimum version aligned for compatibility.
- **License alignment**: LICENSE/NOTICE added and README updated to reference official FluffOS license sources.

## Get the code

```bash
git clone https://github.com/FengYunCalm/fluffos-src.git
cd fluffos-src
```

This README stays at source-repository scope. It does not claim any packaged distribution or hosted deployment path.

## Documentation

- Official docs: https://www.fluffos.info
- Local docs entry: `docs/index.md`
- Changelog for this fork: `CHANGELOG.md`
- For full feature lists and historical notes, see upstream documentation.

## Contributing

See `CONTRIBUTING.md` for guidelines and scope.

## Security

Please report vulnerabilities responsibly. See `SECURITY.md`.

## Code of Conduct

See `CODE_OF_CONDUCT.md`.

## License & Attribution

- MIT License — see `LICENSE`.
- Official license text references:
  - https://www.fluffos.info (License & Copyright)
  - `docs/index.md`
- Historical LPmud/MudOS restrictions apply to legacy components; see `Copyright`.
- Third-party licenses: see `NOTICE` and `src/thirdparty/*`.

## Upstream

- https://github.com/fluffos/fluffos
