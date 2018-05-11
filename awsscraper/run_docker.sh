#!/bin/bash

docker stop awsscraper || true

docker run -d --rm \
	-p 127.0.0.1:80:5000 \
	-e "AWS_REGION=$AWS_REGION" \
	-e "AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID" \
	-e "AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY" \
	-e "AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN" \
	-e "AWS_SECURITY_TOKEN=$AWS_SECURITY_TOKEN" \
	--name "awsscraper" \
	awsscraper:latest . 
