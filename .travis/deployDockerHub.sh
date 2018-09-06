#!/bin/bash

echo "Docker Login"
echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
echo "Pushing to Dockerhub"

if [[ $TRAVIS_BRANCH =~ ^develop$ ]]
then
    echo "Develop Build: Pushing develop tag"
    
    echo $(docker tag $REPO:$TAG $REPO:develop)
    echo $(docker tag $REPO:$TAG $REPO:develop-$TRAVIS_BUILD_NUMBER)

    echo $(docker push $REPO:develop)
    echo $(docker push $REPO:develop-$TRAVIS_BUILD_NUMBER)
elif [ "$TRAVIS_BRANCH" = "$TRAVIS_TAG" ]
then
    echo "Tagged Release: Pushing versioned docker image." 
    echo $(docker tag $REPO:$TAG $REPO:$TRAVIS_TAG)
    echo $(docker tag $REPO:$TAG $REPO:latest)
    echo $(docker push $REPO:$TRAVIS_TAG)
    echo $(docker push $REPO:latest)
else
    echo "Feature Branch: Pushing only branch Tag"
    echo $(docker push $REPO:$TAG)
fi