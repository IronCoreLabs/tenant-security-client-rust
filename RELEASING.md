# Release to GitHub

- Make sure all changes to be released are on `main`
- Compare `main`'s commit history to the changelog to ensure all public API changes are included as well as notable internal changes
  - If necessary, PR and merge the changelog changes.
- Run the [Bump Version](https://github.com/IronCoreLabs/ironcore-documents/actions/workflows/bump-version.yaml) workflow in this repo.
  - Give it a new release version. For example, if the current version is 1.2.3-pre.4, type in 1.2.3.

# Release to crates.io

- `git checkout <tag>` where `<tag>` is the GitHub tag created by the Bump Version workflow above.
- `cargo package` to see if there are any issues
- `cargo publish`
- Check crates.io and docs.rs sites for new version
