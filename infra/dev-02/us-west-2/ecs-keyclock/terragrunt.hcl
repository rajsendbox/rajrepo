terraform {
  source = "../../../../../infra-tf-module/modules/ecs-service-nlb"
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

dependency "alb"{
    config_path = "../../../../../infra-api-layer/env/${local.env}/${local.aws_region}/nlb"
}

dependency "ecs_cluster" {
  config_path = "../../../../../infra-api-layer/env/${local.env}/${local.aws_region}/ecs-cluster"
}

dependency "vpc" {
  config_path = "../../../../../infra-static-resources/env/${local.env}/${local.aws_region}/vpc"
}

inputs = {
  ecs_service = merge(local.config,{
  cluster_arn = dependency.ecs_cluster.outputs.ecs_cluster_arn
  service_connect_configuration = merge(local.config.service_connect_configuration,{
    namespace: dependency.ecs_cluster.outputs.namespace
  })
  vpc_id = dependency.vpc.outputs.vpc_id
  subnet_ids = dependency.vpc.outputs.private_subnet_id
  load_balancer_arn = dependency.alb.outputs.load_balancer_arn
  })
}

