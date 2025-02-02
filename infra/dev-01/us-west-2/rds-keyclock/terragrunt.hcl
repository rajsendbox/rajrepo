terraform {
  source = "../../../../../infra-tf-module/modules/rds"
}

locals {
  account_vars = read_terragrunt_config(find_in_parent_folders("account.hcl"))

  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))

  environment_vars = read_terragrunt_config(find_in_parent_folders("env.hcl"))

  config = jsondecode(file("./config.json"))

  account_id   = local.account_vars.locals.aws_account_id
  aws_region   = local.region_vars.locals.aws_region
  env          = local.environment_vars.locals.env
}


include "root" {
  path = find_in_parent_folders()
}

dependency "security-grp"{
  config_path = "../rds-keyclock-sg"
}

inputs = merge(
  local.config,
  {
    vpc_id = "vpc-0271035982f67f7e8"
    vpc_security_group_ids = [dependency.security-grp.outputs.security_groups_id]
    db_subnet_group_name = "default-vpc-0271035982f67f7e8"
    tag = {
      Environment = local.env
    }
  }
)