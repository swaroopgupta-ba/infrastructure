# Terraform Scripts
This is a repository for CSYE 6225 Assignment 2 - Setting up infrastructure on AWS using Terraform

## Dependencies

* ### Install and Configure AWS Command Line Interface
    - Install and configure AWS Command Line Interface (CLI) on your development machine (laptop). See Install the AWS Command Line Interface on [Linux](https://docs.aws.amazon.com/cli/latest/userguide/install-linux.html) for detailed instructions.
    - Create profiles for your AWS account
    - Configure [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)

* ### Install Terraform
  - [Terraform](https://www.terraform.io/)

## Getting Started

1. Clone the repository to your local machine
2. cd infrastructure
3. To initialize the project as terraform project, run
```
terraform init
```

## Select the AWS CLI profile

To use Dev Environment, run 

```
export AWS_PROFILE=dev
```

To use Prod Environment, run

```
export AWS_PROFILE=prod
```
## To deploy infrastructure with Terraform

Run the following commands in order:

```
terraform plan - Preview the changes Terraform will make to match your configuration.
terraform apply -  Make the planned changes.
```
## To destroy infrastructure with Terraform

```
terraform destroy - Delete all the resources
```