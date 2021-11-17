locals {
  //vpc options
  enable_dns_support               = true
  enable_dns_hostnames             = true
  enable_classiclink_dns_support   = true
  assign_generated_ipv6_cidr_block = false
}

resource "random_string" "s3_bucket_name" {
  upper   = false
  lower   = true
  special = false
  length  = 3
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
    values = ["csye6225-*"]
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
  skip_final_snapshot =  true
}

resource "aws_s3_bucket" "s3" {
  bucket = "${random_string.s3_bucket_name.id}.${var.aws_profile}.${var.s3_domain}"
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
        echo "{\"db_host\":\"${aws_db_instance.csye6225.endpoint}\",\"db_user\":\"csye6225\",\"db_password\":\"${var.password}\",\"default_database\":\"csye6225\",\"db_port\":3306,\"s3_bucket\":\"${aws_s3_bucket.s3.bucket}\"}" > config.json
        cd ..
        sudo chmod -R 777 server
    EOF
}

resource "aws_iam_role" "ec2_s3_access_role" {
  name               = "EC2-CSYE6225-webapp"
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
  tags = {
    Name = "CodeDeployEC2ServiceRole"
  }
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
              "s3:PutObject",
              "s3:deleteObject"
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


// #ec2
// resource "aws_instance" "csye6225_webapp" {

//   depends_on = [aws_db_instance.csye6225]
//   ami           = data.aws_ami.csye_6225_custom_ami.id
//   instance_type = "t2.micro"
//   vpc_security_group_ids  = [aws_security_group.application.id]
//   disable_api_termination = false

//   subnet_id = aws_subnet.vpc_01_subnet[0].id
//   key_name  = var.ec2_key

//   root_block_device {
//     delete_on_termination = true
//     volume_size           = 20
//     volume_type           = "gp2"
//   }

//   iam_instance_profile = "${aws_iam_instance_profile.s3_profile.name}"
//     user_data = data.template_file.config_data.rendered

//   tags = {
//     Name = "csye-6225-webapp-instance"
//   }
    
// }

resource "aws_launch_configuration" "as_conf" {
  name                   = "asg_launch_config"
  image_id               =  data.aws_ami.csye_6225_custom_ami.id
  instance_type          = "t2.micro"
  security_groups        = ["${aws_security_group.application.id}"]
  key_name               = var.ec2_key
  iam_instance_profile   = "${aws_iam_instance_profile.s3_profile.name}"
  associate_public_ip_address = true
  user_data                   = data.template_file.config_data.rendered

  root_block_device {
    volume_type           = "gp2"
    volume_size           = 20
    delete_on_termination = true
  }
  depends_on = [aws_s3_bucket.s3, aws_db_instance.csye6225]
}


# CodeDeploy-EC2-S3 policy allows EC2 instances to read data from S3 buckets. This policy is required for EC2 instances to download latest application revision.
resource "aws_iam_role_policy" "CodeDeploy_EC2_S3" {
  name = "CodeDeploy-EC2-S3"
  role = "${aws_iam_role.ec2_s3_access_role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:Get*",
        "s3:List*",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::codedeploy.${var.aws_profile_name}.${var.domain_Name}/*",
        "arn:aws:s3:::webapp.${var.aws_profile_name}.${var.domain_Name}/*"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_policy" "gh_upload_s3" {
  name   = "gh_upload_s3"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                  "s3:Get*",
                  "s3:List*",
                  "s3:PutObject",
                  "s3:DeleteObject",
                  "s3:DeleteObjectVersion"
            ],
            "Resource": [
                "arn:aws:s3:::codedeploy.${var.aws_profile_name}.${var.domain_Name}",
                "arn:aws:s3:::codedeploy.${var.aws_profile_name}.${var.domain_Name}/*"
              ]
        }
    ]
}
EOF
}

# GH-Code-Deploy Policy for GitHub Actions to Call CodeDeploy

resource "aws_iam_policy" "GH_Code_Deploy" {
  name   = "GH-Code-Deploy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:application:${aws_codedeploy_app.code_deploy_app.name}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": [
         "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentgroup:${aws_codedeploy_app.code_deploy_app.name}/${aws_codedeploy_deployment_group.code_deploy_deployment_group.deployment_group_name}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentconfig:CodeDeployDefault.AllAtOnce"
      ]
    }
  ]
}
EOF
}


# IAM Role for CodeDeploy
resource "aws_iam_role" "code_deploy_role" {
  name = "CodeDeployServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "ghactions-app_user_policy" {
  name   = "ghactions-app_user_policy"
  policy = <<-EOF
  {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": [
          "ec2:AttachVolume",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CopyImage",
          "ec2:CreateImage",
          "ec2:CreateKeypair",
          "ec2:CreateSecurityGroup",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:DeleteKeyPair",
          "ec2:DeleteSecurityGroup",
          "ec2:DeleteSnapshot",
          "ec2:DeleteVolume",
          "ec2:DeregisterImage",
          "ec2:DescribeImageAttribute",
          "ec2:DescribeImages",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeRegions",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSnapshots",
          "ec2:DescribeSubnets",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes",
          "ec2:DetachVolume",
          "ec2:GetPasswordData",
          "ec2:ModifyImageAttribute",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifySnapshotAttribute",
          "ec2:RegisterImage",
          "ec2:RunInstances",
          "ec2:StopInstances",
          "ec2:TerminateInstances"
        ],
        "Resource" : "*"
      }]
  }
  EOF

}



#CodeDeploy App and Group for webapp
resource "aws_codedeploy_app" "code_deploy_app" {
  compute_platform = "Server"
  name             = "csye6225-webapp"
}

resource "aws_codedeploy_deployment_group" "code_deploy_deployment_group" {
  app_name               = "${aws_codedeploy_app.code_deploy_app.name}"
  deployment_group_name  = "csye6225-webapp-deployment"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  service_role_arn       = "${aws_iam_role.code_deploy_role.arn}"
  autoscaling_groups = ["${aws_autoscaling_group.autoscaling.name}"]

  ec2_tag_filter {
    key   = "Name"
    type  = "KEY_AND_VALUE"
    value = "csye-6225-webapp-instance"
  }

  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }

  depends_on = [aws_codedeploy_app.code_deploy_app]
}


data "aws_caller_identity" "current" {}

locals {
  aws_user_account_id = "${data.aws_caller_identity.current.account_id}"
}

# Attach the policy for CodeDeploy role for webapp
resource "aws_iam_role_policy_attachment" "AWSCodeDeployRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
  role       = "${aws_iam_role.code_deploy_role.name}"
}

resource "aws_iam_user_policy_attachment" "ghactions-app_ec2_policy_attach" {
  user       = "ghactions-app"
  policy_arn = "${aws_iam_policy.ghactions-app_user_policy.arn}"
}

resource "aws_iam_user_policy_attachment" "ghactions-app_s3_policy_attach" {
  user       = "ghactions-app"
  policy_arn = "${aws_iam_policy.gh_upload_s3.arn}"
}


resource "aws_iam_user_policy_attachment" "ghactions-app_codedeploy_policy_attach" {
  user       = "ghactions-app"
  policy_arn = "${aws_iam_policy.GH_Code_Deploy.arn}"
}

# data "aws_instance" "myinstance" {
  
#   filter {
#     name = "tag:Name"
#     values = ["myEC2Instance"]
#   }
# }


# add/update the DNS record api.dev.yourdomainname.tld. to the public IP address of the EC2 instance 
data "aws_route53_zone" "selected" {
  name         = "${var.domain_Name}"
  private_zone = false
}

# resource "aws_route53_record" "www" {
#   zone_id = data.aws_route53_zone.selected.zone_id
#   # name    = "api.${data.aws_route53_zone.selected.name}"
#   name    = "${var.domain_Name}"

#   type    = "A"
#   ttl     = "60"
#   records = ["${data.aws_instance.myinstance.public_ip}"]
# }

resource "aws_iam_role_policy_attachment" "AmazonCloudWatchAgent" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = "${aws_iam_role.ec2_s3_access_role.name}"
}


#Autoscaling Group
resource "aws_autoscaling_group" "autoscaling" {
  name                 = "autoscaling-group"
  launch_configuration = "${aws_launch_configuration.as_conf.name}"
  min_size             = 3
  max_size             = 5
  default_cooldown     = 60
  desired_capacity     = 3
  vpc_zone_identifier = ["${aws_subnet.vpc_01_subnet[0].id}"]
  target_group_arns = ["${aws_lb_target_group.albTargetGroup.arn}"]
  tag {
    key                 = "Name"
    value               = "myEC2Instance"
    propagate_at_launch = true
  }
}
# load balancer target group
resource "aws_lb_target_group" "albTargetGroup" {
  name     = "albTargetGroup"
  port     = "8000"
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.vpc_01.id}"
  tags = {
    name = "albTargetGroup"
  }
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 5
    timeout             = 5
    interval            = 30
    path                = "/healthstatus"
    port                = "8000"
    matcher             = "200"
  }
}

#Autoscalling Policy
resource "aws_autoscaling_policy" "WebServerScaleUpPolicy" {
  name                   = "WebServerScaleUpPolicy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = "${aws_autoscaling_group.autoscaling.name}"
  cooldown               = 60
  scaling_adjustment     = 1
}

resource "aws_autoscaling_policy" "WebServerScaleDownPolicy" {
  name                   = "WebServerScaleDownPolicy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = "${aws_autoscaling_group.autoscaling.name}"
  cooldown               = 60
  scaling_adjustment     = -1
}

resource "aws_cloudwatch_metric_alarm" "scaleDown" {
  alarm_name                = "terraform-scaleDown"
  comparison_operator       = "LessThanOrEqualToThreshold"
  evaluation_periods        = "2"
  metric_name               = "CPUUtilization"
  namespace                 = "AWS/EC2"
  period                    = "120"
  statistic                 = "Average"
  threshold                 = "3"
  alarm_description         = "Scale Down when average cpu is below 3%"
  alarm_actions             = ["${aws_autoscaling_policy.WebServerScaleDownPolicy.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_metric_alarm" "scaleUp" {
  alarm_name                = "terraform-scaleUp"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "2"
  metric_name               = "CPUUtilization"
  namespace                 = "AWS/EC2"
  period                    = "120"
  statistic                 = "Average"
  threshold                 = "5"
  alarm_description         = "Scale Up when average cpu is below 5%"
  alarm_actions     = ["${aws_autoscaling_policy.WebServerScaleUpPolicy.arn}"]

  insufficient_data_actions = []
}


#Load Balancer Security Group
resource "aws_security_group" "loadBalancer" {
  name   = "loadBalance_security_group"
  vpc_id = "${aws_vpc.vpc_01.id}"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name        = "LoadBalancer Security Group"
    Environment = "${var.aws_profile_name}"
  }
}


#Load balancer
resource "aws_lb" "application-Load-Balancer" {
  name               = "application-Load-Balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["${aws_security_group.loadBalancer.id}"]
  subnets            = "${aws_subnet.vpc_01_subnet.*.id}"
  ip_address_type    = "ipv4"
  tags = {
    Environment = "${var.aws_profile_name}"
    Name        = "applicationLoadBalancer"
  }
}

resource "aws_lb_listener" "webapp-Listener" {
  load_balancer_arn = "${aws_lb.application-Load-Balancer.arn}"
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.albTargetGroup.arn}"
  }
}

# end 