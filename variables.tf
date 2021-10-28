variable "vpc_cider" {
  type        = string
  description = "VPC Cider Block"
}

variable "vpc_name" {
  type        = string
  description = "VPC Cider Block"
}
variable "subnet_cidrs" {
  type        = list(string)
  description = "Public Subnet Cider Blocks"
}

variable "subnet_az" {
  type        = list(string)
  description = "Public Subnet Availability Zones"
}

variable "subnet_names" {
  type        = list(string)
  description = "Public Subnet Name Tags"
}

variable "password" {
  type        = string
  description = "RDS Password"
}

variable "ec2_key" {
  type        = string
  description = "ec2 key pair"
}

variable "aws_profile" {
  type        = string
  description = "AWS account profile to create resources in"
}

variable "s3_domain" {
  type = string
}

variable "s3_name" {
  type = string
}