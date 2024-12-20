group "default" {
    targets = ["parent", "enclave"]
}

target "parent" {
    context = "./parent"
    dockerfile = "Dockerfile"
    args = {
        TARGETPLATFORM = "x86_64-unknown-linux-gnu"
    }
    platforms = ["linux/amd64"]
    tags = ["parent-vault:latest"]
    cache-to = ["type=gha,ignore-error=true,mode=max,scope=parent"]
    cache-from = ["type=gha,scope=parent"]
}

target "enclave" {
    context = "./enclave"
    dockerfile = "Dockerfile"
    args = {
        TARGETPLATFORM = "x86_64-unknown-linux-musl"
    }
    platforms = ["linux/amd64"]
    tags = ["enclave-vault:latest"]
    cache-to = ["type=gha,ignore-error=true,mode=max,scope=enclave"]
    cache-from = ["type=gha,scope=enclave"]
}