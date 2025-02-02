terraform {
  source = "../../../../../infra-tf-module/modules/lambda"
}

locals {
  account_vars     = read_terragrunt_config(find_in_parent_folders("account.hcl"))
  region_vars      = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  environment_vars = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  config           = jsondecode(file("./config.json"))

  account_id = local.account_vars.locals.aws_account_id
  aws_region = local.region_vars.locals.aws_region
  env        = local.environment_vars.locals.env
}

include "root" {
  path = find_in_parent_folders()
}

inputs = local.config