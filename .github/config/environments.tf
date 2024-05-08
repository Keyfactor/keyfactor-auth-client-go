module "keyfactor_github_test_environment_ad_10_5_0" {
  source = "git::ssh://git@github.com/Keyfactor/terraform-module-keyfactor-github-test-environment-ad.git?ref=main"

  gh_environment_name = "KFC_10_5_0"
  gh_repo_name        = data.github_repository.repo.name
  keyfactor_hostname  = var.keyfactor_hostname_10_5_0
  keyfactor_username  = var.keyfactor_username_10_5_0
  keyfactor_password  = var.keyfactor_password_10_5_0
}

# module "keyfactor_github_test_environment_11_5_0_ad" {
#   source = "git::ssh://git@github.com/Keyfactor/terraform-module-keyfactor-github-test-environment-ad.git?ref=v1.0.0"
#
#   gh_environment_name = "KFC_11_5_0_AD"
#   gh_repo_name        = data.github_repository.repo.name
#   keyfactor_hostname  = var.keyfactor_hostname_11_5_0_AD
#   keyfactor_username  = var.keyfactor_username_11_5_0_AD
#   keyfactor_password  = var.keyfactor_password_11_5_0_AD
# }

module "keyfactor_github_test_environment_11_5_0_kc" {
  source = "git::ssh://git@github.com/Keyfactor/terraform-module-keyfactor-github-test-environment-kc.git?ref=main"

  gh_environment_name     = "KFC_11_5_0_KC"
  gh_repo_name            = data.github_repository.repo.name
  keyfactor_hostname      = var.keyfactor_hostname_11_5_0_KC
  keyfactor_client_id     = var.keyfactor_client_id_11_5_0
  keyfactor_client_secret = var.keyfactor_client_secret_11_5_0
  keyfactor_auth_hostname = var.keyfactor_auth_hostname_11_5_0_KC
}
