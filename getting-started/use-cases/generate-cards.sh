#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026  Authors of KubeArmor

check_prereq()
{
	command -v yq >/dev/null 2>&1 || { echo "yq tool not found" && exit 1; }
	command -v realpath >/dev/null 2>&1 || { echo "realpath tool not found" && exit 1; }
}

get_field()
{
		cat $tmpl | yq ".[$cno].$1"
}

get_references()
{
	for((rid=0;rid<20;rid++)); do
		r_title=$(get_field "details.references.[$rid].title")
		r_url=$(get_field "details.references.[$rid].url")
		[[ "$r_title" == "null" ]] || [[ "$r_url" == "null" ]] && break
		[[ $rid -eq 0 ]] && echo "## References"
		echo -en "[$r_title]($r_url)<br />"
	done
}

get_screenshots()
{
	for((sid=0;sid<20;sid++)); do
		s_title=$(get_field "details.screenshots.[$sid].title")
		s_path=$(get_field "details.screenshots.[$sid].path")
		[[ "$s_title" == "null" ]] && break
		[[ $sid -eq 0 ]] && echo "## Screenshots"
		cat <<EOF
### $s_title
![]($s_path)

EOF
	done
}

get_protection_policies()
{
	for((pid=0;pid<20;pid++)); do
		p_name=$(get_field "details.protectionpolicies.[$pid].name")
		p_yaml=$(get_field "details.protectionpolicies.[$pid].path")
		[[ "$p_name" == "null" ]] || [[ "$p_yaml" == "null" ]] && break
		[[ $pid -eq 0 ]] && echo "## Policy"
		p_simulation=$(get_field "details.protectionpolicies.[$pid].simulation")
		echo -en "### $p_name\n\`\`\`yaml\n$(cat $p_yaml)\n\`\`\`\n"
		if [ "$p_simulation" != "" ]; then
			[[ ! -f "$p_simulation" ]] && echo "!!!!! $p_simulation FILE NOT FOUND" && exit 1
			cat $p_simulation
		fi
	done
}

card_process()
{
	c_title=$(get_field "title")
	c_content=$(get_field "content")

    c_name="${c_title// /-}"
    c_name="${c_name//\//_}"
    card_md="$base_md"
	cat << EOF >> $card_md

<details><summary><h2>$c_title: $c_content</h2></summary>

### Description
$(get_field "details.narrative")

### Attack Scenario
$(get_field "details.attackscenario")

### Compliance
$(get_field "details.compliance")

$(get_protection_policies)

$(get_references)

$(get_screenshots)

</details>

EOF
#	card_create
}

card_create()
{
	cat <<EOF>> $base_md
- title: $c_title
  content: $c_content
  image: $(get_field "image")
  url: $card_md

EOF
}

card_header_create()
{
	cat << EOF > $base_md
<!-- (This is an auto-generated file. Do not edit manually.) -->

# KubeArmor Use-Cases

EOF
}

card_footer_create()
{
	cat << EOF >> $base_md
<!-- (This is an auto-generated file. Do not edit manually.) -->

EOF
}

verify_template()
{
	echo "verifying template $tmpl ..."
	err=$(yq $tmpl 2>&1 >/dev/null)
	if [ "$err" != "" ]; then
		yq $tmpl
		echo "$tmpl validation failed ..."
		exit 1
	fi
}

main()
{
	[[ ! -f "$1" ]] || [[ ! $1 =~ .template$ ]] && echo "Input template not specified" && echo "Usage: $0 <template-file>" && exit 1
	check_prereq
	tmpl=$(realpath $1)
	verify_template
	cd $(dirname $0)
	base_md=${tmpl/.template/.md}
	echo "generating $base_md ..."
	card_header_create
	for((cno=0;cno<1000;cno++)); do
		card=$(cat $tmpl | yq ".[$cno]")
		[[ "$card" == "null" ]] && break
		card_process
	done
	card_footer_create
	echo "processing done"
}

# Processing starts here
main $*

