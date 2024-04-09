#!/bin/bash

current_date_time="`date "+%Y-%m-%d %H:%M:%S"`";
echo "$current_date_time INFO     Starting crawling service | Runs every $CRAWLER_RESTART_TIMEOUT seconds!";

while true; do
  # Record start time
  start_time="$(date -u +%s)"

  # Start crawler
  python3 main.py --urlscan_domains --dirbust;

  # Record end time and elapsed time
  end_time="$(date -u +%s)"
  elapsed="$(($end_time-$start_time))"

  # Sleep for a time, at but not a negative amount of time
  minimum_sleep_time=0  # 100 seconds margin for waits for ELK etc.
  sleep_time=$(( minimum_sleep_time > $(($CRAWLER_RESTART_TIMEOUT - $elapsed - 100)) ? minimum_sleep_time : $(($CRAWLER_RESTART_TIMEOUT - $elapsed - 100)) ))

  # Let it sleep for the remaining period of time before next crawling session
  current_date_time="`date "+%Y-%m-%d %H:%M:%S"`";
  echo "$current_date_time INFO     Now sleeping for $sleep_time seconds";
  sleep $sleep_time;
done