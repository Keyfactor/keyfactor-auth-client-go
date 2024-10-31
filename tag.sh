RC_VERSION=rc.2
TAG_VERSION_1=v1.0.0-$RC_VERSION
git tag -d $TAG_VERSION_1 || true
git tag $TAG_VERSION_1
git push origin $TAG_VERSION_1