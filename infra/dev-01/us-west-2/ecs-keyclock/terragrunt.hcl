terraform {
  source = "../../../../../infra-tf-module/modules/ecs-service"
}

locals {
  account_vars = read_terragrunt_config(find_in_parent_folders("account.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  environment_vars = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  config = jsondecode(file("${get_terragrunt_dir()}/config.json"))

  account_id = local.account_vars.locals.aws_account_id
  aws_region = local.region_vars.locals.aws_region
  env = local.environment_vars.locals.env

}

include "root" {
  path = find_in_parent_folders()
}

dependency "rds"{
  config_path = "../rds-keyclock"
}
dependency "password"{
  config_path = "../keyclock-paasword"
}

inputs = {
  ecs_service = merge(local.config,{
  cluster_arn = "merumesh-cluster"
  service_connect_configuration = merge(local.config.service_connect_configuration,{
    namespace: "merumesh-cluster"
  })
  vpc_id = "vpc-0271035982f67f7e8"
  subnet_ids = ["subnet-086e6bfe4e2c26b40","subnet-0519c1c57ce033d5b"]
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-west-2:211125324484:loadbalancer/app/merumesh-cluster/84128c7fc05713b9"
  })
}