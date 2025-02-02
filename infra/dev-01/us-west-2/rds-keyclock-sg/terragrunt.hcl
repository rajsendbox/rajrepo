terraform {
  source = "../../../../../infra-tf-module/modules/security-group"
}

locals {
  account_vars = read_terragrunt_config(find_in_parent_folders("account.hcl"))

  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))

  environment_vars = read_terragrunt_config(find_in_parent_folders("env.hcl"))

  account_id   = local.account_vars.locals.aws_account_id
  aws_region   = local.region_vars.locals.aws_region
  env          = local.environment_vars.locals.env
  config       = jsondecode(file("./config.json"))
}

include "root" {
  path = find_in_parent_folders()
}

inputs = {
  security_group = merge(
    local.config.security_group,
    {
      vpc_id = "vpc-0271035982f67f7e8",
      tags = merge(
        local.config.security_group.tags,
        {
          Environment = local.env
        }
      )
    }
  )
}
