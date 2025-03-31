RC_VERSION=rc.0
TAG_VERSION=v1.2.1-$RC_VERSION
git tag -d $TAG_VERSION || true
git tag $TAG_VERSION
git push origin $TAG_VERSION