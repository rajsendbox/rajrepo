terraform {
  source = "../../../../../infra-tf-module/modules/api-gateway"
}

locals {
  account_vars     = read_terragrunt_config(find_in_parent_folders("account.hcl"))
  region_vars      = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  environment_vars = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  config           = jsondecode(file("${get_terragrunt_dir()}/config.json"))

  account_id = local.account_vars.locals.aws_account_id
  aws_region = local.region_vars.locals.aws_region
  env        = local.environment_vars.locals.env

}

include "root" {
  path = find_in_parent_folders()
}

dependency "vpc" {
  config_path = "../../../../../infra-static-resources/env/${local.env}/${local.aws_region}/vpc"
}

dependency "ecs_service" {
  config_path = "../ecs-keyclock"
}

inputs = merge(local.config, {
  subnets         = dependency.vpc.outputs.private_subnet_id
  integration_uri = dependency.ecs_service.outputs.listener_arn
  })

