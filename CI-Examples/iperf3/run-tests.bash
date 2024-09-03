#!/bin/bash

# defaults
retries=5
verbose=0

print_msg (){
    echo "********************************************************************************"
    echo "---------- $1"
    echo "********************************************************************************"
}

usage() {
    print_msg "Usage: $0 [-n <RESULT_RAW_NAME>] [-i <RETRIES=5>] [-v] -- PERF_CLIENT_ARGS"
    exit 1
}

write_results_to_file (){
    if [ ! -f "$results_file" ]; then
        print_msg "Writing results to $results_file"
        echo -e $header_row > $results_file
    else
        print_msg "Appending results to $results_file"
    fi
    echo -e $result_row >> $results_file
}

trap_int (){
    print_msg "Writing what we have so far to $results_file"
    write_results_to_file
    exit 1
}

while getopts "n:i:v" o; do
    case "${o}" in
        n)
            result_row_name="${OPTARG}"
            ;;
        i)
            retries=${OPTARG}
            ;;
        v)
            verbose=1
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if [ -z "$result_row_name" ]; then
    usage
fi

block_size=( 1460 1024 512 256 128 64 32 16 )
results_file="results-`date -I`.csv"
header_row="Block Size"
result_row="$result_row_name"
prefix="sudo ip netns exec client_ns"

trap trap_int INT

for bs in ${block_size[@]}
do
  print_msg "Now testing with block size: $bs"
  header_row="${header_row},$bs"
  accumulated_thrgpt=""
  for r in $(seq $retries); do
    output="$($prefix ./iperf3 $@ -l $bs -f m )"
    es=$?
    if [ $es -ne 0 ]; then
      echo -e "$output"
      print_msg "iperf failed. Aborting test.";
      exit $es
    else
      if [ $verbose -eq 1 ]; then
        echo -e "$output"
      fi
    fi

    thrgpt=$(echo "$output" | awk '/receiver/ {print $7; exit}')
    print_msg "Run throughput: $thrgpt Mbps"

    accumulated_thrgpt=$( echo "print($accumulated_thrgpt + $thrgpt)" | python )
    sleep 1
  done

  avg_thrgpt=$( echo "print(round($accumulated_thrgpt / $retries, 2 ))" | python )
  print_msg "Block size ($bs) average throughput: $avg_thrgpt Mbps"

  result_row="${result_row},$avg_thrgpt"
  sleep .5
done

write_results_to_file

print_msg "Done!"
