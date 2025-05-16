#!/bin/sh
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.

# This script builds a debian package for foks via docker, so should work on most platforms.


usage() {
    echo "Usage: $0 -p {arm64|amd64} [-g]"
    exit 1
}

sign=0

while getopts ":p:g" opt; do
    case $opt in
        p)
            plat=$OPTARG
            ;;
        g)
            sign=1
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            usage
            ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            usage
            ;;
    esac
done
shift $((OPTIND -1))

if [ $# -ne 0 ]; then
   usage
fi

if [ ! -f ".top" ]; then
    echo "This script must be run from the root of the foks repository."
    exit 1
fi

arch_sffx=""
case $plat in
    arm64)
        arch_sffx="aarch64"
        ;;
    amd64)
        arch_sffx="x86_64"
        ;;
    *)
        echo "Invalid platform: $plat"
        usage
        ;;
esac

(git diff --quiet && git diff --cached --quiet)
if [ $? -ne 0 ]; then
    echo "Working directory is dirty. Please commit or stash changes before building."
    exit 1
fi

docker_plat=linux/${arch_sffx}
if [ "$plat" != "arm64" ] && [ "$plat" != "amd64" ]; then
    usage
fi

vversion=$(git tag --list | grep -E '^v[0-9]+\.' | sort -V | tail -1)
version=$(echo $vversion | sed 's/^v//')

if [ -z "$version" ]; then
    echo "No version found. Please tag the commit with a version."
    exit 1
fi

echo "Building foks version $version for ${docker_plat}"

docker_tag=foks-rpm-${version}-${arch_sffx}

workdir=build/rpm

build_docker() {
    docker build \
        -f dockerfiles/rpm-pkg.dev \
        --build-arg PLAT=${plat} \
        --platform=${docker_plat} \
        -t ${docker_tag} \
        .
}

run_docker() {
    docker run \
        --rm \
        --platform=${docker_plat} \
        -v $(pwd)/build/rpm:/root/workspace \
        ${docker_tag} \
        -c "\
        cd /root && \
        cp workspace/*.tar.gz rpmbuild/SOURCES/ && \
        cp workspace/*.spec rpmbuild/SPECS/ && \
        rpmbuild -ba rpmbuild/SPECS/foks.spec && \
        rpmbuild -bs rpmbuild/SPECS/foks.src.spec && \
        cp rpmbuild/RPMS/*/*.rpm workspace && \
        cp rpmbuild/SRPMS/*.rpm workspace"
}

make_tarball() {
    tmp=$(mktemp -d)
    git archive --format=tar.gz --output=${tmp}/x.tar.gz HEAD
    (cd ${tmp} && \
        mkdir foks-${version} &&  \
        cd foks-${version} &&  \
        tar -xzf ../x.tar.gz &&  \
        cd .. && \
        rm -f x.tar.gz && \
        tar -czf foks-${version}.tar.gz foks-${version}
    )
    cp ${tmp}/foks-${version}.tar.gz ${workdir}/foks-${version}.tar.gz
}

make_spec() {
    local is_src=$1
    filename=foks.spec
    if [ $is_src -eq 1 ]; then
        filename=foks.src.spec
    fi
    path=build/rpm/${filename}
    cat <<EOF > ${path}
%define debugsource_package %{nil}
%global _debugsource_template %{nil}
Name: foks
Version: ${version}
Release: 1%{?dist}
Summary: Access the Federated Open Key Service (FOKS) 

License: MIT
URL: https://github.com/foks-proj/go-foks
Source0: %{name}-%{version}.tar.gz

BuildRequires: pcsc-lite-devel
EOF
    if [ $is_src -eq 1 ]; then
        cat <<EOF >> ${path}
BuildRequires: golang >= 1.23
EOF
    fi
    cat <<EOF >> ${path}
Requires: pcsc-lite-devel

%description
FOKS is a federated protocol that allows for online public key advertisement,
sharing, and rotation. It works for a user and their many devices, for many users who want
to form a group, for groups of groups etc. The core primitive is that several
private key holders can conveniently share a private key; and that private key
can simply correspond to another public/private key pair, which can be members
of a group one level up. This pattern can continue recursively forming a tree.

Crucially, if any private key is removed from a key share, all shares rooted at
that key must rotate. FOKS implements that rotation.

Like email or the Web, the world consists of multiple FOKS servers, administrated
independently and speaking the same protocol. Groups can span multiple federated
services.

Many applications can be built on top of this primitive but best suited are those
that share encrypted, persistent information across groups of users with multiple
devices. For instance, files and git hosting.

%prep
%autosetup # unpacks Source0 into %{_builddir}/%{name}-%{version}

%build
EOF
    if [ $is_src -eq 0 ]; then
        cat <<EOF >> ${path}
export PATH=/usr/local/go/bin:\$PATH
EOF
    fi
    cat <<EOF >> ${path}
export GOPATH=\$(mktemp -d)
mkdir -p \$GOPATH/src/github.com/foks-proj
ln -sf %{_builddir}/%{name}-%{version} \$GOPATH/src/github.com/foks-proj/go-foks
pushd \$GOPATH/src/github.com/foks-proj/go-foks/client/foks
go build -o %{name}
mv %{name} ../..
popd

%install
mkdir -p %{buildroot}/%{_bindir}
install -m 0755 %{name} %{buildroot}/%{_bindir}/%{name}
pushd %{buildroot}/%{_bindir}
ln -s %{name} git-remote-foks
popd

%files
%{_bindir}/%{name}
%{_bindir}/git-remote-foks

%changelog
EOF
    go tool github.com/foks-proj/go-tools/changelog-linux-pkg rpm < changelog.yml >> ${path}

}

clean_house() {
    mv build/rpm/*.rpm build/
    rm -rf build/rpm
}

do_sign() {
    cd build
    if [ $sign -eq 1 ]; then
        echo "Signing RPMs..."
        rpm --addsign foks-${version}-1.el8.${arch_sffx}.rpm
        rpm --addsign foks-debuginfo-${version}-1.el8.${arch_sffx}.rpm
        rpm --addsign foks-${version}-1.el8.src.rpm
    fi
}

mkdir -p ${workdir}
build_docker
make_tarball
make_spec 1
make_spec 0
run_docker
clean_house
(do_sign)