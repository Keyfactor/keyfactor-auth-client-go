RC_VERSION=rc.10
TAG_VERSION_1=v0.0.1-$RC_VERSION
git tag -d $TAG_VERSION_1 || true
git tag $TAG_VERSION_1
git push origin $TAG_VERSION_1