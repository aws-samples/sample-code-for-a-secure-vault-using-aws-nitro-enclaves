FROM chef as builder
ARG TARGETPLATFORM

COPY --from=planner /app/recipe.json recipe.json
RUN cargo install cargo-chef --locked
RUN cargo chef cook --release --target $TARGETPLATFORM --recipe-path recipe.json
COPY . .
RUN cargo build --target $TARGETPLATFORM --release --color never

####################################################################################################
## Final image
####################################################################################################
FROM public.ecr.aws/lts/ubuntu:latest
ARG TARGETPLATFORM

WORKDIR /app

# Copy our build
COPY --from=builder /app/target/${TARGETPLATFORM}/release/parent-vault /app/parent-vault

CMD ["/app/parent-vault", "--host", "127.0.0.1"]
