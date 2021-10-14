output "vpc_id" {
  value = aws_vpc.vpc_01.id
}

output "aws_internet_gateway_id" {
  value = aws_internet_gateway.vpc_01_internet-gateway.id
}

output "aws_subnet_id" {
  value = { for k, v in aws_subnet.vpc_01_subnet : k => v.id }
}

output "route-table_id" {
  value = aws_route_table.vpc_01_route-table.id
}
