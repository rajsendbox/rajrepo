terraform {
  source = "../../../../../infra-tf-module/modules/aws-secret"
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

dependency "rds"{
  config_path = "../rds-keyclock"
}
dependency "password"{
  config_path = "../keyclock-paasword"
}
inputs = {
  secrets = [
    for secrets in local.config.secrets : 
      merge(
      secrets,
      {
        secret_string = merge(
          secrets.secret_string,{
          KC_DB_USERNAME = dependency.rds.outputs.db_username
          KC_DB_PASSWORD = dependency.rds.outputs.password
          KC_DB_URL = "jdbc:postgresql://${dependency.rds.outputs.db_host}/postgres"
          port = 5432
          KEYCLOAK_ADMIN = "admin"
          KEYCLOAK_ADMIN_PASSWORD = dependency.password.outputs.password
          }
        )
        tags = merge(
          secrets.tags,
          {
            Environment = local.env
          })
        }
      )
  ]
}
