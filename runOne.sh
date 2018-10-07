#!/bin/bash

#
# Test of ftrace/latency under varying load provided by iperf
#


B="----------------"


TARGET_IPV4="10.10.1.2"

IPERF_TARGET_IPV4="10.10.1.2"

PING_ARGS="-D -i 0.5 -s 56"

NATIVE_PING_CMD="${HOME}/contools-bpf/iputils/ping"
CONTAINER_PING_CMD="/iputils/ping"

PING_CONTAINER_IMAGE="chrismisa/contools:ping-ubuntu"
PING_CONTAINER_NAME="ping-container"

PAUSE_CMD="sleep 5"

PING_PAUSE_CMD="sleep 1500"
# PING_PAUSE_CMD="sleep 5"

DATE_TAG=`date +%Y%m%d%H%M%S`
META_DATA="Metadata"

# declare -a IPERF_ARGS=("1M" "3M" "10M" "32M" "100M" "316M" "1G" "3G" "10G")
declare -a IPERF_ARGS=("nop" "1M" "10M" "100M" "1G" "10G" "100G")
# declare -a IPERF_ARGS=("nop" "500K" "1M" "100M" "1G" "10G")
# declare -a IPERF_ARGS=("1M")

OLD_PWD=$(pwd) # used in the scripts referenced below to get at functions in this dir

RUN1="${OLD_PWD}/run_trace.sh"

mkdir $DATE_TAG
cd $DATE_TAG

# Get some basic meta-data
echo "uname -a -> $(uname -a)" >> $META_DATA
echo "docker -v -> $(docker -v)" >> $META_DATA
echo "lsb_release -a -> $(lsb_release -a)" >> $META_DATA
echo "sudo lshw -> $(sudo lshw)" >> $META_DATA

# Start ping container as service
docker run -itd \
  --name=$PING_CONTAINER_NAME \
  --entrypoint=/bin/bash \
  $PING_CONTAINER_IMAGE
echo $B Started $PING_CONTAINER_NAME $B

$PAUSE_CMD

#
# Code to get net dev indexes
#
INNER_DEV_NAME="eth0" # Note that adding the '@' selects only the veth end
OUTER_DEV_NAME="eno1d1"

# # Grab container's network namespace and put it somewhere useful
# PING_CONTAINER_PID=`docker inspect -f '{{.State.Pid}}' $PING_CONTAINER_NAME`
# mkdir -p /var/run/netns
# ln -sf /proc/$PING_CONTAINER_PID/ns/net /var/run/netns/$PING_CONTAINER_NAME
# # Get the device indexes
# OUTER_DEV_INDEX=`ip l | grep ${OUTER_DEV_NAME} | cut -d ':' -f 1`
# INNER_DEV_INDEX=`ip netns exec $PING_CONTAINER_NAME ip l | grep ${INNER_DEV_NAME} | cut -d ':' -f 1`
# 
# echo Got outer dev index: $OUTER_DEV_INDEX, inner dev index: $INNER_DEV_INDEX

echo $B Running inner dev strategy $B

mkdir inner_dev
cd inner_dev
source $RUN1
cd ..

docker stop $PING_CONTAINER_NAME
docker rm $PING_CONTAINER_NAME
echo $B Stopped container $B

echo Done.
