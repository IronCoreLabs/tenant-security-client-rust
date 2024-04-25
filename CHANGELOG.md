## 0.2.0

Breaking changes:

- Changed several functions to take RNG as `Arc<Mutex<R>>` instead of `&mut R`. This allows for these functions to be called concurrently.

## 0.1.0

- Initial release
