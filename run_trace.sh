#!/bin/bash

#
# Test of inner dev plug in scheme
#
MONITOR_CMD="${OLD_PWD}/latency.py $BPF_PROG $OUTER_DEV_NAME $INNER_DEV_NAME"

for arg in ${IPERF_ARGS[@]}
do
  echo $arg >> file_list
  # Start iperf
  if [ $arg != "nop" ]
  then
    iperf -c $IPERF_TARGET_IPV4 -d -i 100 -b $arg -t 0 \
      > ${arg}.iperf &
    IPERF_PID=$!
  fi



  #
  # Native pings for control
  #
  echo $B Native control $B
  # Run ping in background
  $NATIVE_PING_CMD $PING_ARGS $TARGET_IPV4 \
    > native_control_${TARGET_IPV4}_${arg}.ping &

  $PAUSE_CMD

  echo "  pinging. . ."
  
  $PAUSE_CMD
  
  PING_PID=`ps -e | grep ping | sed -E 's/ *([0-9]+) .*/\1/'`
  echo "  got ping pid: $PING_PID"
  
  $PING_PAUSE_CMD
  
  kill -INT $PING_PID
  echo "  killed ping"
  
  $PAUSE_CMD

  #
  # Container pings for control
  #
  echo $B Container control $B
  # Start ping in container
  docker exec $PING_CONTAINER_NAME \
    $CONTAINER_PING_CMD $PING_ARGS $TARGET_IPV4 \
    > container_control_${TARGET_IPV4}_${arg}.ping &
  echo "  pinging. . ."

  $PAUSE_CMD
  
  PING_PID=`ps -e | grep ping | sed -E 's/ *([0-9]+) .*/\1/'`
  echo "  got ping pid: $PING_PID"
  
  $PING_PAUSE_CMD

  kill -INT $PING_PID
  echo "  killed ping"

  $PAUSE_CMD

  #
  # Container pings with monitoring
  #
  echo $B Container / native monitored $B
  
  docker exec $PING_CONTAINER_NAME \
    $CONTAINER_PING_CMD $PING_ARGS $TARGET_IPV4 \
    > container_monitored_${TARGET_IPV4}_${arg}.ping &
  echo "  container pinging. . ."

  $PAUSE_CMD
  
  PING_PID=`ps -e | grep ping | sed -E 's/ *([0-9]+) .*/\1/'`
  echo "  got container ping pid $PING_PID"

  $MONITOR_CMD $PING_PID > container_monitored_${TARGET_IPV4}_${arg}.latency &
  MONITOR_PID=$!
  echo "  monitor running with pid: ${MONITOR_PID}"
  
  $PAUSE_CMD
  

  # Run ping in background
  $NATIVE_PING_CMD $PING_ARGS $TARGET_IPV4 \
    > native_monitored_${TARGET_IPV4}_${arg}.ping &
  NAT_PING_PID=$!
  echo "  native pinging. . . (pid $NAT_PING_PID)"
  
  
  $PING_PAUSE_CMD
  
  kill -INT $PING_PID
  kill -INT $NAT_PING_PID
  echo "  killed pings"
  
  $PAUSE_CMD
  
  kill -INT $MONITOR_PID
  echo "  killed monitor"
  
  $PAUSE_CMD


  if [ $arg != "nop" ]
  then
    kill -INT $IPERF_PID
    echo "  killed iperf"
  fi

  $PAUSE_CMD

done
