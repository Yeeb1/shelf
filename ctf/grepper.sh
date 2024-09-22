#!/bin/bash

show_help() {
    echo "Usage: $0 [--all] [--path=dir1] [--path=dir2] ... [--verbose] [--auto] [--quick] [--gzip] [keyword1 [keyword2 ...]]"
    echo "  --all           Include binary files in the search."
    echo "  --path=dir      Specify one or more directories to begin searching from. Can be repeated."
    echo "  --verbose       Print detailed command output to the console as the script runs."
    echo "  --auto          Automatically generate keywords from usernames in /home and append hostname with .htb."
    echo "  --quick         Quickly search default directories /opt and /var, plus any uncommon directories in /."
    echo "  --gzip          Enable searching within gzip compressed files."
    echo "  keywordX        Specify keywords to search for in the files. Optional if --auto or --quick is used."
}

common_dirs=("bin" "boot" "dev" "etc" "home" "lib" "lib32" "lib64" "libx32" "lost+found" "media" "mnt" "opt" "proc" "root" "run" "sbin" "srv" "sys" "tmp" "usr" "var")

grep_options="-i"
verbose=0
auto_mode=0
quick_mode=0
gzip_enabled=0
declare -a search_paths
declare -a keywords

echo "Parsing command line options..."
while (( "$#" )); do
    case "$1" in
        --all)
            grep_options+=" -a"
            echo "Including binary files in the search."
            shift
            ;;
        --path=*)
            search_paths+=("${1#*=}")
            echo "Adding search path: ${1#*=}"
            shift
            ;;
        --verbose)
            verbose=1
            echo "Verbose mode enabled."
            shift
            ;;
        --auto)
            auto_mode=1
            echo "Auto mode enabled."
            shift
            ;;
        --quick)
            quick_mode=1
            echo "Quick search mode enabled. Using default paths /opt and /var."
            search_paths=("/opt" "/var")
            shift
            ;;
        --gzip)
            gzip_enabled=1
            echo "Gzip search mode enabled."
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            keywords+=("$1")
            echo "Adding keyword: $1"
            shift
            ;;
    esac
done

if [[ $quick_mode -eq 1 ]]; then
    echo "Checking for uncommon directories in /..."
    for dir in /*; do
        if [[ -d "$dir" && ! " ${common_dirs[@]} " =~ " $(basename "$dir") " ]]; then
            echo "Uncommon directory found: $dir"
            search_paths+=("$dir")
        fi
    done
fi

if [[ $auto_mode -eq 1 && ${#keywords[@]} -eq 0 ]]; then
    echo "Generating keywords automatically..."
    for dir in /home/*; do
        if [[ -d "$dir" ]]; then
            user=$(basename "$dir")
            keywords+=("$user")
            echo "Keyword added from username: $user"
        fi
    done
    hostname=$(hostname)
    keywords+=("${hostname}.htb")
    echo "Keyword added from hostname: ${hostname}.htb"
fi

grepper_dir="./grepper"
mkdir -p "$grepper_dir"
echo "Output directory created at: $grepper_dir"

search_files() {
    local keyword=$1
    local path=$2
    local base_output_file="${grepper_dir}/${keyword}_from_${sanitized_path}"
    local regular_output_file="${base_output_file}.txt"
    local gzip_output_file="${base_output_file}_gzip.txt"

    local search_cmd="grep -H $grep_options '$keyword' 2>/dev/null"
    local gzip_search_cmd="zgrep -H $grep_options '$keyword' 2>/dev/null"

    echo "Searching regular files for '$keyword' in $path..."
    find $path -type f ! -name '*.gz' -print0 2>/dev/null | xargs -0 -I {} bash -c "grep -H $grep_options '$keyword' '{}' >> '$regular_output_file' 2>/dev/null"

    if [[ $gzip_enabled -eq 1 ]]; then
        echo "Running gzip search command on gzipped files from $path"
            find $path -type f -name '*.gz' -print0 2>/dev/null | xargs -0 -I {} bash -c "zgrep -H $grep_options '$keyword' '{}' >> '$gzip_output_file' 2>/dev/null"
    fi

    if [[ $verbose -eq 1 ]]; then
        echo "Results for '$keyword' in regular files stored in $regular_output_file"
        cat "$regular_output_file"
        if [[ $gzip_enabled -eq 1 ]]; then
            echo "Results for '$keyword' in gzipped files stored in $gzip_output_file"
            cat "$gzip_output_file"
        fi
    else
        echo "Results for '$keyword' in regular files stored in $regular_output_file"
        if [[ $gzip_enabled -eq 1 ]]; then
            echo "Results for '$keyword' in gzipped files stored in $gzip_output_file"
        fi
    fi
}

for keyword in "${keywords[@]}"; do
    for path in "${search_paths[@]}"; do
        sanitized_path=$(echo "$path" | sed 's/[^a-zA-Z0-9]/_/g')
        output_file="${grepper_dir}/${keyword}_from_${sanitized_path}.txt"
        echo "Starting search for $keyword in $path..."
        search_files "$keyword" "$path" "$output_file"
        if [[ $verbose -eq 1 ]]; then
            echo "Results for '$keyword' stored in $output_file"
            cat "$output_file"
        else
            echo "Results for '$keyword' stored in $output_file"
        fi
    done
done
