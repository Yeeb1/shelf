#!/bin/bash

log_output() {
    echo "$1" >> "$LOG_FILE"
}

handle_error() {
    if [ $? -ne 0 ]; then
        echo "[x] Error: $1 failed. Check the log file ($LOG_FILE) for details."
        exit 1
    fi
}

print_info() {
    echo "[+] $1"
}

print_success() {
    echo "[+] $1 - Done"
}

if [ $# -eq 0 ]; then
    echo "[x] Usage: $0 <aws-profile>"
    exit 1
fi

PROFILE=$1
LOG_FILE="${PROFILE}_output.log"

> "$LOG_FILE"

print_info "Using AWS Profile: $PROFILE"

print_info "Fetching AWS account details..."
aws sts get-caller-identity --output table --profile "$PROFILE" >> "$LOG_FILE"
handle_error "AWS account identity"
print_success "AWS account details retrieved"

print_info "Fetching EC2 Instance names..."
aws ec2 describe-instances --query 'Reservations[*].Instances[*].Tags[?Key==`Name`].Value' --output table --profile "$PROFILE" >> "$LOG_FILE"
handle_error "EC2 Instance names"
print_success "EC2 Instance names retrieved"

print_info "Fetching S3 Bucket names..."
aws s3api list-buckets --query 'Buckets[*].Name' --output table --profile "$PROFILE" >> "$LOG_FILE"
handle_error "S3 Bucket names"
print_success "S3 Bucket names retrieved"

print_info "Fetching RDS Instance names..."
aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier' --output table --profile "$PROFILE" >> "$LOG_FILE"
handle_error "RDS Instance names"
print_success "RDS Instance names retrieved"

print_info "Fetching VPCs..."
aws ec2 describe-vpcs --query 'Vpcs[*].{ID:VpcId,CIDR:CidrBlock}' --output table --profile "$PROFILE" >> "$LOG_FILE"
handle_error "VPCs"
print_success "VPCs retrieved"

print_info "Fetching Security Groups..."
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId,GroupName]' --output table --profile "$PROFILE" >> "$LOG_FILE"
handle_error "Security Groups"
print_success "Security Groups retrieved"

print_info "Fetching IAM Users..."
aws iam list-users --query "Users[*].[UserName,CreateDate]" --output table --profile "$PROFILE" >> "$LOG_FILE"
handle_error "IAM Users"
print_success "IAM Users retrieved"

print_info "Fetching IAM Roles..."
aws iam list-roles --query "Roles[*].[RoleName,CreateDate]" --output table --profile "$PROFILE" >> "$LOG_FILE"
handle_error "IAM Roles"
print_success "IAM Roles retrieved"

print_info "All data fetched successfully. Check the log file (${LOG_FILE}) for details."
