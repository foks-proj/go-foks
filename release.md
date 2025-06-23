# Manual Release Checklist (should be automated at some point)

- Run tests
  - `make proto && make ci`

- Version bump
  - Change version in lib/core/version.go 
  - Make a relaese data in changelog.yml
  - `git commit -am "Bump version to vX.Y.Z" && git push`
  - `git tag vX.Y.Z && git push --tags`

- Make a new Github Release
  - `gh release create`

-  Debian
  - `make deb`
  - cd build && gh release upload vX.Y.Z foks_*.deb
  - cd ../pkgs 
  - cp ../go-foks/build/foks_*.deb public/pool/main/f/
  - git commit -a -m "Add foks_*.deb to public pool"
  - git push
  - startup debian VM
  - ssh max@192.168.56.5
  - cd src/pkgs
  - git pull
  - bash -x scripts/make-debian-repo.bash
  - git add public/stable
  - git commit -a -m 'vX.Y.Z'
  - git push
  - wait about 10 minutes
  - sudo apt update
  - sudo apt upgrade

- RHEL / Fedora / etc
  - `make rpm`
  - cd build && gh release upload vX.Y.Z foks-*.rpm
  - cd ../pkgs
  - git pull
  - mkdir rpm-in
  - cd rpm-in && cp ../go-foks/build/foks-*.rpm .
  - cd ..
  - git add rpm-in
  - git commit -a -m "Add foks-*.rpm to public pool"
  - git push
  - startup fedora VM
  - ssh -A max@192.168.56.7
  - cd src/pkgs
  - git pull
  - bash -x scripts/make-fedora-repo.bash
  - git add public/stable
  - git commit -a -m 'vX.Y.Z'
  - git push
  - wait about 10 minutes
  - sudo dnf upgrade --refresh

- static Linux
  - make musl
  - cd build && gh release upload vX.Y.Z foks-linux-musl

- brew 
  - make brew
  - cd build && gh release upload vX.Y.Z foks-darwin-x86_64.tar.gz
  - cd ../pkgs && git pull && cp ../go-foks/build/foks-*.zip public/stable/darwin/
  - cp ../go-foks/changelog.yml public/stable/changelog.yml
  - git add public/stable/darwin/foks-*.zip
  - git commit -a -m "Add foks-*.zip to public pool"
  - git push
  - cd ../../homebrew-cask/Casks/f
  - git fetch upstream master
  - git checkout master
  - git reset --hard upstream/master
  - vim foks.rb
  - update version and sha256s
  - commit -a -m 'foks vX.Y.Z'
  - cp foks.rb /opt/homebrew/Library/Taps/homebrew-releaser/homebrew-test/Casks/foks.rb 
  - brew install --cask homebrew-releaser/homebrew-test/foks  # to test
  - brew audit --cask homebrew-releaser/homebrew-test/foks # to test
  - cd pkgs && git pull
  - go to github and open PR against homebrew/homebrew-cask

- choco
  - make choco
  - cd build && gh release upload vX.Y.Z foks*win*.zip
  - open windows laptop
  - cd src/go-foks
  - git pull
  - bash -x scripts/make-choco.bash
  - cd pkg/choco
  - choco install foks --version=X.Y.Z --source=C:\Users/THEMA\src\go-foks\pkg\choco
  - choco push ./foks.X.Y.Z.nupkg --source https://push.chocolatey.org/
  - git commit -a -m "choco"
  - git push

- Update server
   - make foks-server-release

