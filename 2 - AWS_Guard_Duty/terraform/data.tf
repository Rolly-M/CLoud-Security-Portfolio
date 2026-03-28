###############################################################################
# Data Sources
###############################################################################

# Current AWS Account
data "aws_caller_identity" "current" {}

# Current AWS Region
data "aws_region" "current" {}

# Availability Zones
data "aws_availability_zones" "available" {
  state = "available"
}