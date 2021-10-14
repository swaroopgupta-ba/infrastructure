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
