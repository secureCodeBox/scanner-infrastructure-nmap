#!/bin/bash

# WARNING!!!!!
# THIS script differs from the other deployToDockerHub Scripts in the other repos!
# This is to support the two build versions "default" and "privileged"

echo "Docker Login"
echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
echo "Pushing to Dockerhub"

if [[ $TRAVIS_BRANCH =~ ^master$ ]]
then
    echo "Develop Build: Pushing develop tag"
    
    echo $(docker tag $REPO:$TAG $REPO:master)
    echo $(docker tag $REPO:$TAG $REPO:unstable)
    echo $(docker tag $REPO:$TAG-privileged $REPO:unstable-privileged)
    echo $(docker tag $REPO:$TAG $REPO:unstable-$TRAVIS_BUILD_NUMBER)

    echo $(docker push $REPO:master)
    echo $(docker push $REPO:unstable)
    echo $(docker push $REPO:unstable-privileged)
    echo $(docker push $REPO:unstable-$TRAVIS_BUILD_NUMBER)
elif [ "$TRAVIS_BRANCH" = "$TRAVIS_TAG" ]
then
    echo "Tagged Release: Pushing versioned docker image." 
    echo $(docker tag $REPO:$TAG $REPO:$TRAVIS_TAG)
    echo $(docker tag $REPO:$TAG-privileged $REPO:$TRAVIS_TAG-privileged)
    echo $(docker tag $REPO:$TAG $REPO:latest)

    echo $(docker push $REPO:$TRAVIS_TAG)
    echo $(docker push $REPO:$TRAVIS_TAG-privileged)
    echo $(docker push $REPO:latest)
else
    echo "Feature Branch: Pushing only branch Tag"
    echo $(docker push $REPO:$TAG)
fi