variable "RELEASE_TAG" {
  default = "dev"
}

variable "RELEASE_DIR" {
  default = "release"
}

group "default" {
  targets = ["controller", "binaries"]
}

target "docker-metadata-action" {}

target "common" {
  context = "."
  dockerfile = "Dockerfile"
  platforms = ["linux/amd64", "linux/arm64"]
  args = {
    VERSION = RELEASE_TAG
  }
  cache-from = ["type=gha,scope=graphwan"]
}

target "controller" {
  inherits = ["common", "docker-metadata-action"]
  target = "controller"
  contexts = {
    agent-amd64 = "target:agent-amd64"
    agent-arm64 = "target:agent-arm64"
  }
  output = ["type=registry"]
  cache-to = ["type=gha,scope=graphwan,mode=max"]
}

target "agent-amd64" {
  inherits = ["common"]
  platforms = ["linux/amd64"]
  target = "build"
}

target "agent-arm64" {
  inherits = ["common"]
  platforms = ["linux/arm64"]
  target = "build"
}

target "binaries" {
  inherits = ["common"]
  target = "binaries"
  output = ["type=local,dest=${RELEASE_DIR},platform-split=false"]
}
