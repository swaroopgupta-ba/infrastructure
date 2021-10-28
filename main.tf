locals {
  //vpc options
  enable_dns_support               = true
  enable_dns_hostnames             = true
  enable_classiclink_dns_support   = true
  assign_generated_ipv6_cidr_block = false
}

resource "aws_vpc" "vpc_01" {
  cidr_block                       = var.vpc_cider
  instance_tenancy                 = "default"
  enable_dns_support               = local.enable_dns_support
  enable_dns_hostnames             = local.enable_dns_hostnames
  enable_classiclink_dns_support   = local.enable_classiclink_dns_support
  assign_generated_ipv6_cidr_block = local.assign_generated_ipv6_cidr_block

  tags = {
    Name = var.vpc_name
  }
}

resource "aws_subnet" "vpc_01_subnet" {
  depends_on              = [aws_vpc.vpc_01]
  count                   = length(var.subnet_cidrs)
  vpc_id                  = aws_vpc.vpc_01.id
  cidr_block              = var.subnet_cidrs[count.index]
  availability_zone       = var.subnet_az[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = var.subnet_names[count.index]
  }
}

resource "aws_internet_gateway" "vpc_01_internet-gateway" {
  depends_on = [aws_vpc.vpc_01]
  vpc_id     = aws_vpc.vpc_01.id

  tags = {
    Name = "Internet gateway for vpc_01"
  }
}

resource "aws_route_table" "vpc_01_route-table" {
  depends_on = [aws_vpc.vpc_01, aws_internet_gateway.vpc_01_internet-gateway]
  vpc_id     = aws_vpc.vpc_01.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.vpc_01_internet-gateway.id
  }

  tags = {
    Name = "vpc_01 Route Table"
  }
}

resource "aws_route_table_association" "vpc_01_subnet-route-table-association" {
  count          = length(var.subnet_cidrs)
  subnet_id      = aws_subnet.vpc_01_subnet[count.index].id
  route_table_id = aws_route_table.vpc_01_route-table.id
}

data "aws_ami" "csye_6225_custom_ami" {
  most_recent = true

  //change to using variables
  owners = ["167171622115", "228157484555"]

  filter {
    name   = "name"
    values = ["csye6225_fall_2021_*"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

resource "aws_security_group" "application" {
  name        = "application"
  description = "EC2 security group for EC2 instances that will host web application"
  vpc_id      = aws_vpc.vpc_01.id

  ingress = [
    {
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      description      = "TLS from VPC"
      cidr_blocks      = [aws_vpc.vpc_01.cidr_block]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      from_port        = 22
      to_port          = 22
      protocol         = "tcp"
      description      = "SSH from VPC"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      from_port        = 80
      to_port          = 80
      protocol         = "tcp"
      description      = "HTTP from VPC"
      cidr_blocks      = [aws_vpc.vpc_01.cidr_block]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description = "NODE application"
      from_port        = 3000
      to_port          = 3000
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids = []
      security_groups = []
      self = false
    }
  ]
  egress = [
    {
      description = "HTTP"
      from_port        = 80
      to_port          = 80
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids = []
      security_groups = []
      self = false
    },
    {
      description = "HTTPS"
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids = []
      security_groups = []
      self = false
    },
    {
      description = "SQL"
      from_port        = 3306
      to_port          = 3306
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids = []
      security_groups = []
      self = false
    },
  ]
  tags = {
    Name = "application"
  }
}

resource "aws_security_group" "database" {

  depends_on  = [aws_vpc.vpc_01, aws_security_group.application]
  name        = "database"
  description = "security group for the database"
  vpc_id      = aws_vpc.vpc_01.id

  ingress = [
    {
      description      = "MYSQL"
      from_port        = 3306
      to_port          = 3306
      protocol         = "tcp"
      cidr_blocks      = [aws_vpc.vpc_01.cidr_block]
      security_groups  = [aws_security_group.application.id]
      self             = false
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
    }
  ]
  tags = {
    Name = "database"
  }
}

#db_subnet_group
resource "aws_db_subnet_group" "rds-subnet" {
  name = "rds-subnet"
  subnet_ids = [aws_subnet.vpc_01_subnet[0].id, aws_subnet.vpc_01_subnet[1].id, aws_subnet.vpc_01_subnet[2].id]

  tags = {
    Name = "rds-subnet"
  }
}

#db parameter group
resource "aws_db_parameter_group" "rds-pg" {
  name   = "rds-pg"
  family = "mysql5.6"
}

#db instance
resource "aws_db_instance" "csye6225" {

  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t3.micro"
  name                   = "csye6225"
  username               = "csye6225"
  password               = var.password
  db_subnet_group_name   = aws_db_subnet_group.rds-subnet.name
  vpc_security_group_ids = [aws_security_group.database.id]

  multi_az                  = false
  identifier                = "csye6225"
  publicly_accessible       = false
  allocated_storage         = 10
  apply_immediately         = true
  backup_retention_period   = 0
  final_snapshot_identifier = true
}

resource "aws_s3_bucket" "s3" {
  bucket = "${var.s3_name}.${var.aws_profile}.${var.s3_domain}"
  acl    = "private"
  force_destroy = true

    lifecycle_rule {
        id      = "long-term"
        enabled = true

        transition {
            days          = 30
            storage_class = "STANDARD_IA"
        }
    }

    server_side_encryption_configuration {
        rule {
            apply_server_side_encryption_by_default {
                sse_algorithm = "aws:kms"
            }
        }
    }
} 

data "template_file" "config_data" {
  template = <<-EOF
		#! /bin/bash
        cd home/ubuntu
        mkdir server
        cd server
        echo "{\"db_host\":\"${aws_db_instance.csye6225.endpoint}\",\"db_user\":\"csye6225\",\"db_password\":\"${var.password}\",\"default_database\":\"csye6225\",\"db_port\":3306,\"s3\":\"${aws_s3_bucket.s3.bucket}\"}" > config.json
        cd ..
        sudo chmod -R 777 server
    EOF
}

resource "aws_iam_role" "ec2_s3_access_role" {
  name               = "EC2-CSYE6225"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_policy" "policy" {
    name = "WebAppS3"
    description = "ec2 will be able to talk to s3 buckets"
    policy = <<-EOF
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
              "s3:ListAllMyBuckets", 
              "s3:GetBucketLocation",
              "s3:GetObject",
              "s3:PutObject"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${aws_s3_bucket.s3.id}",
                "arn:aws:s3:::${aws_s3_bucket.s3.id}/*"
            ]
        }
    ]
    }
    EOF

}

resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = aws_iam_role.ec2_s3_access_role.name
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_iam_instance_profile" "s3_profile" {                             
    name  = "s3_profile_3"                         
    role = aws_iam_role.ec2_s3_access_role.name
}


#ec2
resource "aws_instance" "csye6225_webapp" {

  depends_on = [aws_db_instance.csye6225]
  ami           = data.aws_ami.csye_6225_custom_ami.id
  instance_type = "t2.micro"
  vpc_security_group_ids  = [aws_security_group.application.id]
  disable_api_termination = false

  subnet_id = aws_subnet.vpc_01_subnet[0].id
  key_name  = var.ec2_key

  root_block_device {
    delete_on_termination = true
    volume_size           = 20
    volume_type           = "gp2"
  }

  iam_instance_profile = "${aws_iam_instance_profile.s3_profile.name}"
    user_data = data.template_file.config_data.rendered
}
