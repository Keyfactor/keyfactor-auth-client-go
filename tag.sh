RC_VERSION=rc.0
TAG_VERSION_1=v1.1.2-$RC_VERSION
git tag -d $TAG_VERSION_1 || true
git tag $TAG_VERSION_1
git push origin $TAG_VERSION_1