group "default" {
    targets = ["parent", "enclave"]
}

target "parent" {
    context = "./parent"
    dockerfile = "Dockerfile"
    args = {
        TARGETPLATFORM = "x86_64-unknown-linux-gnu"
    }
    tags = ["parent-vault:latest"]
}

target "enclave" {
    context = "./enclave"
    dockerfile = "Dockerfile"
    args = {
        TARGETPLATFORM = "x86_64-unknown-linux-musl"
    }
    tags = ["enclave-vault:latest"]
}