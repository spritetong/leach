# leach

This is an extension of [build-helper](https://crates.io/crates/build-helper), which provides great convenience for FFI and cross compilation.

## Features

- `build-helper`: Core functionality from the original `build-helper` crate
- `cmake`: Additional utilities and helpers for:
  - FFI build configuration
  - Platform-specific build customization
  - CMake build system integration with [cmkabe](https://github.com/spritetong/cmkabe.git)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
leach = "0.2.2"
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a PR.

## Contact

For any questions or feedback, please contact me at [spritetong@gmail.com](mailto:spritetong@gmail.com).
