#!/usr/bin/env bash
set -euo pipefail

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: apply.sh [--check] [AOSP_ROOT]

Apply the ASPin patches to an AOSP checkout initialized from base.xml.
If AOSP_ROOT is omitted, the current directory is used. With --check, all
baseline, cleanliness, checksum, and git-apply checks run without modifying
the checkout.
EOF
}

mode=apply
if [[ ${1:-} == --check ]]; then
    mode=check
    shift
elif [[ ${1:-} == -h || ${1:-} == --help ]]; then
    usage
    exit 0
fi

[[ $# -le 1 ]] || {
    usage >&2
    exit 2
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
archive="$script_dir/patches.tar.zst"
base_manifest="$script_dir/base.xml"
aosp_root=${1:-$PWD}
aosp_root=$(cd -- "$aosp_root" 2>/dev/null && pwd -P) || die "AOSP root does not exist: ${1:-$PWD}"

for command_name in git mktemp sha256sum tar zstd; do
    command -v "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
done

[[ -f "$archive" ]] || die "patch archive not found: $archive"
[[ -f "$base_manifest" ]] || die "base manifest not found: $base_manifest"
[[ -d "$aosp_root/.repo" ]] || die "not an AOSP repo checkout (missing .repo): $aosp_root"

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/aspin-patches.XXXXXX")
cleanup() {
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

zstd -q -d -c -- "$archive" | tar -xf - -C "$tmp_dir"
patch_root="$tmp_dir/patches"
[[ -d "$patch_root" ]] || die "archive is missing patches/"
[[ -f "$patch_root/series" ]] || die "archive is missing patches/series"
[[ -f "$patch_root/SHA256SUMS" ]] || die "archive is missing patches/SHA256SUMS"

(
    cd -- "$patch_root"
    sha256sum -c SHA256SUMS
)

declare -a records=()
while IFS='|' read -r project_path base_commit patch_file; do
    [[ -z "$project_path" || "$project_path" == \#* ]] && continue
    [[ -n "$base_commit" && -n "$patch_file" ]] || die "invalid series entry: $project_path|$base_commit|$patch_file"
    [[ "$project_path" != /* && "$project_path" != *'..'* ]] || die "unsafe project path in series: $project_path"
    [[ "$patch_file" =~ ^[A-Za-z0-9._-]+$ ]] || die "unsafe patch filename in series: $patch_file"
    [[ "$base_commit" =~ ^[0-9a-f]{40}$ ]] || die "invalid base commit in series: $base_commit"
    records+=("$project_path|$base_commit|$patch_file")
done < "$patch_root/series"

[[ ${#records[@]} -gt 0 ]] || die "patch series is empty"

printf 'Preflighting ASPin patches against %s\n' "$aosp_root"
for record in "${records[@]}"; do
    IFS='|' read -r project_path base_commit patch_file <<< "$record"
    project_dir="$aosp_root/$project_path"
    patch_path="$patch_root/$patch_file"

    [[ -d "$project_dir" ]] || die "project directory not found: $project_dir"
    [[ -f "$patch_path" ]] || die "patch file not found: $patch_path"

    GIT_DISCOVERY_ACROSS_FILESYSTEM=1 git -C "$project_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
        || die "not a Git worktree: $project_dir"

    actual_commit=$(GIT_DISCOVERY_ACROSS_FILESYSTEM=1 git -C "$project_dir" rev-parse HEAD)
    [[ "$actual_commit" == "$base_commit" ]] \
        || die "$project_path is at $actual_commit; expected baseline $base_commit"

    dirty_state=$(GIT_DISCOVERY_ACROSS_FILESYSTEM=1 git -C "$project_dir" status --porcelain --untracked-files=all)
    [[ -z "$dirty_state" ]] \
        || die "$project_path has local changes; start from a clean base.xml checkout"

    GIT_DISCOVERY_ACROSS_FILESYSTEM=1 git -C "$project_dir" apply \
        --check --binary --whitespace=error-all "$patch_path"
    printf '  OK  %s @ %s\n' "$project_path" "$base_commit"
done

if [[ "$mode" == check ]]; then
    printf 'ASPin patch preflight completed; no files were modified.\n'
    exit 0
fi

declare -a applied_records=()
for record in "${records[@]}"; do
    IFS='|' read -r project_path base_commit patch_file <<< "$record"
    project_dir="$aosp_root/$project_path"
    patch_path="$patch_root/$patch_file"

    if ! GIT_DISCOVERY_ACROSS_FILESYSTEM=1 git -C "$project_dir" apply \
        --binary --whitespace=error-all "$patch_path"; then
        printf 'Patch application failed for %s; rolling back earlier projects.\n' "$project_path" >&2
        for ((index=${#applied_records[@]} - 1; index >= 0; index--)); do
            IFS='|' read -r rollback_project rollback_patch <<< "${applied_records[$index]}"
            GIT_DISCOVERY_ACROSS_FILESYSTEM=1 git -C "$aosp_root/$rollback_project" apply \
                --reverse --binary "$patch_root/$rollback_patch" || true
        done
        die "failed to apply $patch_file"
    fi
    applied_records+=("$project_path|$patch_file")
    printf '  APPLIED  %s\n' "$project_path"
done

for record in "${records[@]}"; do
    IFS='|' read -r project_path base_commit patch_file <<< "$record"
    GIT_DISCOVERY_ACROSS_FILESYSTEM=1 git -C "$aosp_root/$project_path" diff --check
done

printf 'ASPin patches applied successfully to %s\n' "$aosp_root"
